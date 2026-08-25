<!--
SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
SPDX-License-Identifier: MIT
-->

# zig-scram-sha-256

Compute PostgreSQL SCRAM-SHA-256 password verifiers in Zig, without sending the
plaintext to the server.

```
SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
```

This is the string PostgreSQL stores in `pg_authid.rolpassword`. Producing it
client-side means `CREATE ROLE` / `ALTER ROLE` can be issued with the verifier
in place of the password, so the plaintext never crosses the wire, never lands
in the server log, and never reaches `pg_stat_activity`.

```sql
ALTER ROLE alice PASSWORD 'SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$...';
```

Requires Zig 0.16.0.

## Install

```sh
zig fetch --save git+<repo-url>
```

```zig
// build.zig
const scram = b.dependency("scram_sha_256", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("scram", scram.module("scram_sha_256"));
```

The only dependency is [uucode], for the Unicode character data behind the
SASLprep step. It is built with just the four fields this module reads.

[uucode]: https://github.com/jacobsandlund/uucode

## Use

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
| `normalization` | `.saslprep` | See below. |

The allocator is only touched when SASLprep has real work to do, which means
never for an all-ASCII password and never for `.raw`.

## CLI

The package also builds a small tool. It reads the password from stdin by
default, since `-p` puts it in the process table where other users can see it.

```console
$ zig build
$ printf 'hunter2' | ./zig-out/bin/scram_sha_256
SCRAM-SHA-256$4096:zLU9phQvqg5BXTM1oxGFsQ==$NokuUG1vCRqy...:l/jd28uhQujg...

$ ./zig-out/bin/scram_sha_256 --help
```

`-i/--iterations`, `-s/--salt-length`, `--raw`, and `--strict-prep` map onto the
options above.

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

## Testing

```sh
zig build test
```

The suite includes the [RFC 7677] §3 test vector. The client proof and server
signature published in that RFC are derived from this StoredKey and ServerKey,
so matching it pins the entire derivation chain.

Both halves have also been checked differentially against independent
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
| `src/scram.zig` | Key derivation, the `Secret` type, parsing and rendering. |
| `src/saslprep.zig` | RFC 4013, following PostgreSQL's implementation. |
| `src/nfkc.zig` | NFKC (UAX #15) over uucode's character data. |
| `src/stringprep_tables.zig` | RFC 3454 range tables, transcribed from `saslprep.c`. |
| `src/main.zig` | The CLI. |

## License

MIT, see `LICENSES/MIT.txt`. Every file carries an SPDX header, so the project
is [REUSE] compliant and `reuse lint` passes.

One caveat worth knowing: the codepoint ranges in `src/stringprep_tables.zig`
are the tables published in RFC 3454, transcribed via PostgreSQL's
`src/common/saslprep.c`. They are covered here by the same MIT grant as
everything else, but if that provenance matters for your use, review it rather
than taking the header at face value.

[REUSE]: https://reuse.software/
[RFC 4013]: https://www.rfc-editor.org/rfc/rfc4013
[RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677
