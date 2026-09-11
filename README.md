<!--
SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
SPDX-License-Identifier: MIT
-->

# zig-scram

SCRAM in Zig — [RFC 5802] and [RFC 7677]: the four-message authentication
exchange, channel binding, and the password verifiers it authenticates
against, over any hash those RFCs name.

It is a library first, with a small CLI alongside it for the one job that is
awkward to do any other way: computing a PostgreSQL verifier by hand.

| | |
|---|---|
| `scram.Client` | The client half of the exchange, as a state machine with no transport in it. |
| `scram.Secret` | A verifier — what a server stores instead of a password. |
| `scram.Mechanism(Hash)` | The same thing over some other hash; `scram` is `Mechanism(Sha256)`. |
| `scram.saslprep` | RFC 4013, which SCRAM runs over a password before hashing it. |

A verifier is the half of SCRAM that PostgreSQL puts in front of its users:

```
SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
```

That is the string it keeps in `pg_authid.rolpassword`. Computing it
client-side means `CREATE ROLE` / `ALTER ROLE` can be issued with the verifier
in place of the password, so the plaintext never crosses the wire, never lands
in the server log, and never reaches `pg_stat_activity`.

```sql
ALTER ROLE alice PASSWORD 'SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$...';
```

Requires Zig 0.16.0.

## Install

```sh
zig fetch --save git+https://git.jcollie.dev/jeff/zig-scram.git
```

```zig
// build.zig
const scram = b.dependency("scram", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("scram", scram.module("scram"));
```

The only dependency is [uucode], for the Unicode character data behind the
SASLprep step. It is built with just the four fields this module reads.

[uucode]: https://github.com/jacobsandlund/uucode

## Where this lives

The canonical repository is on my Forgejo instance:

```sh
git clone https://git.jcollie.dev/jeff/zig-scram.git
```

It is also published on [Radicle], a peer-to-peer network where a repository
has no canonical host — it lives on whichever nodes choose to seed it. Its
Repository ID is:

```
rad:z3p1EVd76fZgybgAPzCpM25LAUCwP
```

With a [Radicle node] running (`rad node start`):

```sh
rad clone rad:z3p1EVd76fZgybgAPzCpM25LAUCwP
```

`clone` consults your node's routing table to find a seed holding the
repository, so no host has to be named. The default branch is `main`, the same
history you would get from the Forgejo instance. To help keep it available,
seed it:

```sh
rad seed rad:z3p1EVd76fZgybgAPzCpM25LAUCwP
```

Zig's package manager does not speak `rad://`, so `zig fetch` still wants the
`git+https` URL above. Radicle is for getting the source, filing issues, and
sending patches without a forge account.

[Radicle]: https://radicle.xyz/
[Radicle node]: https://radicle.xyz/#get-started

## Verifiers

```zig
const std = @import("std");
const scram = @import("scram");

var threaded: std.Io.Threaded = .init(gpa, .{});
defer threaded.deinit();

// Fresh random salt, PostgreSQL's own defaults: 16 salt bytes, 4096 rounds.
const secret = try scram.generate(gpa, threaded.io(), "hunter2", .{});

std.debug.print("{f}\n", .{secret});
// SCRAM-SHA-256$4096:6/+BSuGpL8lOjQ12JyH+JQ==$immDsh...:nWB1yw...
```

`Secret` is a plain value with no owned memory, so it can be copied, stored, and
returned freely. Render it with the `{f}` placeholder, or:

```zig
var buf: [scram.max_encoded_length]u8 = undefined;
const text = try secret.bufPrint(&buf);      // no allocation

const owned = try secret.toOwnedString(gpa); // caller frees
```

Read one back, and check a password against it:

```zig
const stored = try scram.Secret.parse(rolpassword);

if (try stored.verify(gpa, attempt, .saslprep)) {
    // Recomputed with the stored salt and iteration count, compared in
    // constant time.
}
```

For a specific salt and round count — reproducing an existing verifier, or
testing:

```zig
const secret = try scram.compute(gpa, password, salt, 4096, .saslprep);
```

`generate` takes `Options`:

| field | default | |
|---|---|---|
| `iterations` | `4096` | PBKDF2 rounds. PostgreSQL 16+ exposes this as the `scram_iterations` GUC. |
| `salt_length` | `16` | Random salt bytes, up to `max_salt_length` (64). |
| `normalization` | `.saslprep` | See [SASLprep](#saslprep). |

The allocator is only touched when SASLprep has real work to do, which means
never for an all-ASCII password and never for `.raw`.

A `Secret` holds no secret material: the plaintext cannot be recovered from it.
It is still enough to impersonate the *server* to a client, though, so a
verifier is sensitive even where it is not a password.

The text format is PostgreSQL's. The RFCs describe what a server has to know,
not how to write it down, so while `ScramSha1.Secret` renders the same shape
under a `SCRAM-SHA-1$` tag, only the SHA-256 spelling is a string PostgreSQL
will accept.

## Authenticating

`Client` is the client half of the exchange, as a state machine with no
transport in it: you hand it what arrived and send what it hands back. It never
opens a socket and never touches TLS.

```zig
var client: scram.Client = try .init(gpa, io, .{
    .username = "user",
    .password = "pencil",
});
defer client.deinit();

try conn.send(client.clientFirst());
try client.handleServerFirst(try conn.receive());
try conn.send(try client.clientFinal());
try client.handleServerFinal(try conn.receive());
```

Both ends prove themselves. Returning from that last call is what
authenticates the **server** — it has shown it knows `ServerKey`, which only
the holder of the verifier does. A client that sends its proof and then treats
the connection as good without getting there has proved itself to a stranger
and learned nothing in return.

Every slice handed back is owned by the `Client` and lives until `deinit`;
every slice passed in is copied if it is needed later, so your buffers are free
immediately. The password is wiped as soon as the key schedule has run, and the
keys as soon as the proofs are computed.

`Client.Options`:

| field | default | |
|---|---|---|
| `username` | — | May be empty. PostgreSQL sends `n=,` because libpq has already named the user in the startup packet. |
| `password` | — | |
| `authzid` | `null` | The authorization identity, when it differs from the authentication one. |
| `channel_binding` | `.none` | See below. |
| `normalization` | `.saslprep` | Applied to the username and authzid as well as the password. |
| `nonce_length` | `24` | Random bytes to draw; the nonce is sent as base64 of them. |
| `nonce` | `null` | Use this nonce verbatim. Only for reproducing published vectors. |
| `minimum_iterations` | `4096` | Refuse a server that asks for fewer rounds than this, which RFC 7677 §4 makes the floor. |

`client.mechanism()` gives the name to negotiate, and `client.authenticated()`
answers whether the exchange completed.

### Channel binding

Set `channel_binding` and the mechanism to negotiate becomes
`SCRAM-SHA-256-PLUS`.

```zig
var client: scram.Client = try .init(gpa, io, .{
    .username = "user",
    .password = "pencil",
    .channel_binding = .{ .bound = .{
        .type = "tls-server-end-point",
        .data = cert_hash,          // you compute this from your TLS stack
    } },
});
```

The binding data is a property of the TLS connection, not of SCRAM, so it is
passed in rather than derived here — which means `tls-server-end-point`,
`tls-exporter` and `tls-unique` all work without this library depending on a
TLS implementation.

The three variants are not preferences. They are assertions about what the
server advertised, and the server checks them:

| | |
|---|---|
| `.none` | This client does not support channel binding. |
| `.unsupported_by_server` | It does, but the server's mechanism list had no `-PLUS` variant. If that list was tampered with, the server knows what it really advertised and will abort. |
| `.bound` | Bind the exchange to the transport. |

### Other hashes

RFC 5802 defines SCRAM generically and instantiates it once, as SCRAM-SHA-1;
RFC 7677 instantiates it again as SCRAM-SHA-256, changing nothing but the hash.
`Mechanism(Hash)` is that parameter made explicit, and `scram` is
`Mechanism(Sha256)` under a shorter name.

```zig
const ScramSha1 = scram.ScramSha1;              // RFC 5802's own
const ScramSha512 = scram.Mechanism(std.crypto.hash.sha2.Sha512);

var client: ScramSha1.Client = try .init(gpa, io, .{ ... });
```

A hash with no registered mechanism name is a compile error rather than a
guess, since the name is what the two ends use to agree on what they are
running. SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and SHA3-512 are accepted;
[References cited](#references-cited) says where each of those names comes
from.

### Errors

`handleServerFirst` rejects a server whose nonce does not extend the client's
(`error.NonceMismatch`) and one asking for too few rounds
(`error.IterationCountTooLow`). `handleServerFinal` returns
`error.ServerSignatureMismatch` when the server cannot prove itself, and
`error.AuthenticationFailed` when it answered `e=` — `client.serverError()`
then says which of RFC 5802's error values it sent, for the log.

Message parsing follows the ABNF rather than accepting anything that could be
understood: attributes must arrive in the order the grammar lists them, and an
`m=` attribute fails the exchange wherever it appears, because it marks an
extension the receiver is required to understand.

## SASLprep

SCRAM does not hash the password bytes directly. It hashes
`SASLprep(password)` — [RFC 4013], a stringprep profile that maps some
characters away, folds some to a space, normalizes to NFKC, and rejects the
rest. Getting this wrong means the verifier silently disagrees with the server
for any password outside ASCII.

The implementation here follows PostgreSQL's `src/common/saslprep.c` rather
than the RFC wherever the two differ, because agreeing with the server is the
whole point. Three behaviours are worth knowing about:

- **All-ASCII passwords short-circuit.** SASLprep is the identity on ASCII, so
  the whole profile is skipped. This is also why an ASCII control character in a
  password never trips the prohibited-output check, even though the table lists
  it.
- **The prohibit and bidi checks run before normalization**, against the mapped
  string rather than the NFKC output, though RFC 3454 describes them as checks
  on the output. PostgreSQL has always done it this way.
- **Failure falls back to the raw bytes.** If a password is not valid UTF-8, or
  contains a prohibited or Unicode-3.2-unassigned character, or breaks the
  bidirectional-text rules, both the server and libpq hash the unprepared bytes
  instead. `.saslprep` does the same.

`Normalization` picks between that and doing nothing:

- `.saslprep` (default) — full SASLprep with the PostgreSQL fallback. Reproduces
  the server's verifier for any password.
- `.raw` — hash the bytes as given. Correct only if the caller has already
  prepared the password, or knows it is pure ASCII.

RFC 5802 also says a client should prepare the *username*, so `Client` runs the
same profile over `username` and `authzid`.

To find out that a password *needed* the fallback rather than silently taking
it, call `scram.saslprep.prep` directly; it returns `error.InvalidUtf8` or
`error.Prohibited` instead. The CLI exposes this as `--strict-prep`.

### Unicode versions

The stringprep range tables are transcribed from PostgreSQL's `saslprep.c`, so
the A.1 unassigned-code-point table stays frozen at Unicode 3.2 exactly as
RFC 3454 specifies. Normalization, on the other hand, uses whatever Unicode
version uucode ships — currently 17.0, against 15.1 in PostgreSQL 17 and 16.0
in PostgreSQL 18.

In practice this gap is unreachable: Unicode's normalization stability policy
freezes a character's decomposition once assigned, so the versions can only
disagree about characters that did not exist in the server's Unicode version.

## The CLI

`scram-sha-256` computes a PostgreSQL verifier and nothing else — it is named
for the one mechanism whose stored format it writes, not for the library. It
reads the password from stdin by default, since `-p` puts it in the process
table where other users can see it.

```console
$ zig build
$ printf 'hunter2' | ./zig-out/bin/scram-sha-256
SCRAM-SHA-256$4096:zLU9phQvqg5BXTM1oxGFsQ==$NokuUG1vCRqy...:l/jd28uhQujg...

$ ./zig-out/bin/scram-sha-256 --help
```

`-i/--iterations`, `-s/--salt-length`, `--raw`, and `--strict-prep` map onto the
options above.

### Shell completions

`zig build install` writes fish and bash completions under the prefix, in the
directories both shells already search:

```console
$ zig build install --prefix ~/.local
$ ls ~/.local/share/fish/vendor_completions.d/scram-sha-256.fish
$ ls ~/.local/share/bash-completion/completions/scram-sha-256
```

Both shells search `$XDG_DATA_HOME` (usually `~/.local/share`) and every prefix
on `$XDG_DATA_DIRS`, so a prefix already on those paths needs no further setup.
bash also needs the `bash-completion` package, which loads the file on demand
the first time `scram-sha-256` is completed. Nothing searches `zig-out`, the
default prefix, so either install to a real prefix or source the files from
`completions/` directly.

## Nix

The flake builds the CLI and provides the development shell this project is
worked on in:

```sh
nix build            # the CLI, with its shell completions, into ./result
nix run . -- --help
nix develop          # zig, reuse, zon2nix, kcov and perf
```

A Nix build has no network, and `zig build` wants one to fetch uucode. The
bridge is `build.zig.zon.nix`, generated from `build.zig.zon` by [zon2nix]: it
evaluates to a directory laid out like Zig's package cache, which `package.nix`
hands to `zig build --system`, so Nix fetches the dependency and the build
itself fetches nothing. Adding, removing or updating a dependency means
regenerating it — never editing it — so that every hash comes from the
manifest:

```sh
nix develop -c zon2nix --16 --nix=build.zig.zon.nix build.zig.zon
```

The dependency directory is also a flake output of its own, for running
`zig build` against something other than the package:

```sh
zig build --system "$(nix build --print-out-paths .#zig-deps)"
```

[zon2nix]: https://github.com/jcollie/zon2nix

## Testing

```sh
zig build test
```

The suite replays both published transcripts end to end — [RFC 7677] §3 for
SCRAM-SHA-256 and [RFC 5802] §5 for SCRAM-SHA-1 — checking every message the
client emits byte for byte, including the proof and the verification of the
server's signature. Between them they pin the whole derivation chain and the
whole wire format, under two different hashes.

The proof is also checked the way a server checks it, from a stored `Secret`
alone: recover `ClientKey` by undoing the XOR, hash it, and compare against
`StoredKey`. That runs against a verifier derived independently of the code
that built the proof.

The SASLprep half has been checked differentially against independent
implementations. Those runs were one-off validations rather than part of the
suite, since they need a Python interpreter and a copy of PostgreSQL's source:

- **NFKC against Python's `unicodedata`** — 292,531 single code points and
  155,704 random sequences, no mismatches. Code points unassigned in Python's
  Unicode 16 were skipped; the stability policy makes that sound.
- **The full SASLprep profile against a Python port of `pg_saslprep`**, reading
  its tables straight out of `saslprep.c` rather than out of this repository —
  331,229 random inputs, no mismatches.

## Layout

| file | |
|---|---|
| `src/scram.zig` | SCRAM-SHA-256: the `Secret` and `Client` everything else aliases. |
| `src/mechanism.zig` | `Mechanism(Hash)` — the key schedule, the verifier, the client state machine. |
| `src/messages.zig` | The RFC 5802 message grammar and the GS2 header. |
| `src/saslprep.zig` | RFC 4013, following PostgreSQL's implementation. |
| `src/nfkc.zig` | NFKC (UAX #15) over uucode's character data. |
| `src/stringprep_tables.zig` | RFC 3454 range tables, transcribed from `saslprep.c`. |
| `src/main.zig` | The CLI. |
| `completions/` | fish and bash completions for the CLI. |

## What is not here

The **server** half of the exchange. `Secret` holds exactly what a server needs
and `src/messages.zig` has the grammar, so it is mostly message-writing, but
nothing here accepts an exchange rather than initiating one.

## References cited

Everything this implementation is answerable to. The note on each says what
this project takes from it, not what the document is about.

### The mechanism

| | |
|---|---|
| [RFC 5802] | *Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms.* The exchange, the message ABNF, the key schedule, the `e=` error values — and SCRAM-SHA-1, its own instantiation. |
| [RFC 7677] | *SCRAM-SHA-256 and SCRAM-SHA-256-PLUS.* The default here, and where §4's floor of 4096 iterations comes from. |
| [RFC 5801] | *GSS-API Mechanisms in SASL: The GS2 Mechanism Family.* The `gs2-header` — the channel-binding flag and authorization identity that open the client's first message and reappear inside `c=`. |
| [RFC 4422] | *Simple Authentication and Security Layer (SASL).* The framework SCRAM is a mechanism of: what authentication and authorization identities are, and how a mechanism comes to be chosen. |
| [draft-melnikov-scram-sha-512] | SCRAM-SHA-512. An expired Internet-Draft. |
| [draft-melnikov-scram-sha3-512] | SCRAM-SHA3-512, likewise — and the one that has to exist, because SHA-3 has no entry in the hash-name registry below, so its mechanism name cannot be derived and must be specified outright. |

### Preparing passwords and usernames

| | |
|---|---|
| [RFC 4013] | *SASLprep: Stringprep Profile for User Names and Passwords.* What `src/saslprep.zig` implements. Formally obsolete — see [RFC 8265] below. |
| [RFC 3454] | *Preparation of Internationalized Strings ("stringprep").* The framework SASLprep is a profile of, and the source of the range tables in `src/stringprep_tables.zig`. |
| [UAX #15] | *Unicode Normalization Forms.* NFKC, the normalization step. |
| [RFC 3629] | *UTF-8.* stringprep is defined over UTF-8, and a password that is not valid UTF-8 is one of the things that triggers the fallback to raw bytes. |
| [RFC 8265] | *PRECIS Profiles for Usernames and Passwords.* Obsoletes RFC 7613, which obsoleted RFC 4013 — so SASLprep has been superseded twice over. Listed because it is deliberately **not** implemented: RFC 7677 still specifies SASLprep and PostgreSQL still uses it, and a verifier that disagrees with the server is worthless however current its string preparation is. |

### Channel binding

| | |
|---|---|
| [RFC 5056] | *On the Use of Channel Bindings to Secure Channels.* What a channel binding is and what attack it closes. |
| [RFC 5929] | *Channel Bindings for TLS.* `tls-unique` and `tls-server-end-point`. |
| [RFC 9266] | *Channel Bindings for TLS 1.3.* `tls-exporter`, which is the binding to use over TLS 1.3, where `tls-unique` is not defined. |

### Primitives

| | |
|---|---|
| [RFC 2104] | HMAC. |
| [RFC 8018] | PKCS #5 v2.1 — PBKDF2, the salted iteration that turns a password into `SaltedPassword`. |
| [FIPS 180-4] | SHA-1 and the SHA-2 family. |
| [FIPS 202] | SHA-3. |
| [RFC 4648] | Base64, which every binary field on the wire and in a verifier is encoded with. |

### IANA registries

| | |
|---|---|
| [SASL Mechanisms] | Registered as the family `SCRAM-*`, so there is no individual `SCRAM-SHA-256` row to look up. |
| [Hash Function Textual Names] | `sha-1`, `sha-224`, `sha-256`, `sha-384`, `sha-512`, and nothing else. RFC 5802 §4 builds a mechanism name by prefixing one of these with `SCRAM-`, which is exactly the set `Mechanism(Hash)` accepts without a draft to point at. |
| [Channel-Binding Types] | The `cb-name` values that may follow `p=`. |

## License

MIT, with one exception: `src/stringprep_tables.zig` is `MIT AND PostgreSQL`,
because it is transcribed from PostgreSQL's `src/common/saslprep.c` — including
that file's merging of adjacent ranges — and the PostgreSQL License requires its
notice be retained. Both licenses are permissive and impose nothing beyond
attribution.

The underlying tables are published in RFC 3454, whose copyright statement
allows derivative works that "assist in its implementation ... without
restriction of any kind", so no further grant is needed for them.

Every file carries an SPDX header and the license texts are in `LICENSES/`, so
the project is [REUSE] compliant and `reuse lint` passes.

Note for anyone distributing a binary built from this: the Unicode character
data reaches you through uucode, which ships the Unicode License alongside its
own MIT license. Nothing to do when consuming this as source, but the Unicode
License asks for its notice in distributions.

[REUSE]: https://reuse.software/
[RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
[RFC 3454]: https://www.rfc-editor.org/rfc/rfc3454
[RFC 3629]: https://www.rfc-editor.org/rfc/rfc3629
[RFC 4013]: https://www.rfc-editor.org/rfc/rfc4013
[RFC 4422]: https://www.rfc-editor.org/rfc/rfc4422
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648
[RFC 5056]: https://www.rfc-editor.org/rfc/rfc5056
[RFC 5801]: https://www.rfc-editor.org/rfc/rfc5801
[RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
[RFC 5929]: https://www.rfc-editor.org/rfc/rfc5929
[RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
[RFC 8018]: https://www.rfc-editor.org/rfc/rfc8018
[RFC 8265]: https://www.rfc-editor.org/rfc/rfc8265
[RFC 9266]: https://www.rfc-editor.org/rfc/rfc9266
[UAX #15]: https://www.unicode.org/reports/tr15/
[FIPS 180-4]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
[FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
[draft-melnikov-scram-sha-512]: https://datatracker.ietf.org/doc/draft-melnikov-scram-sha-512/
[draft-melnikov-scram-sha3-512]: https://datatracker.ietf.org/doc/draft-melnikov-scram-sha3-512/
[SASL Mechanisms]: https://www.iana.org/assignments/sasl-mechanisms/
[Hash Function Textual Names]: https://www.iana.org/assignments/hash-function-text-names/
[Channel-Binding Types]: https://www.iana.org/assignments/channel-binding-types/
