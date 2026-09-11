// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! SCRAM ([RFC 5802]) as a family, parameterized by its hash function.
//!
//! RFC 5802 defines the mechanism generically and instantiates it once, as
//! SCRAM-SHA-1. [RFC 7677] instantiates it again as SCRAM-SHA-256, changing
//! nothing but the hash. `Mechanism(Hash)` is that parameter made explicit:
//! `Mechanism(Sha256)` is RFC 7677, `Mechanism(Sha1)` is RFC 5802's own, and
//! the message grammar they share lives in `messages.zig`.
//!
//! Two things come out of it. The first is the key schedule, which is all a
//! password verifier needs:
//!
//!     SaltedPassword := PBKDF2-HMAC(SASLprep(password), salt, i, hash_length)
//!     ClientKey      := HMAC(SaltedPassword, "Client Key")
//!     StoredKey      := H(ClientKey)
//!     ServerKey      := HMAC(SaltedPassword, "Server Key")
//!
//! The second is `Client`, which runs the four-message exchange those keys
//! exist for. The split matters: a server stores `StoredKey` and `ServerKey`
//! and can verify a login without ever holding `ClientKey`, which is why a
//! stolen verifier does not let the thief log in as the user — though it does
//! let them impersonate the *server* to that user, so a verifier is still
//! sensitive.
//!
//! ## What is proved, and to whom
//!
//! The exchange authenticates both ends. The client proves it knows
//! `ClientKey` by sending `ClientProof`, and the server proves it knows
//! `ServerKey` by sending `ServerSignature` — so a client that runs
//! `handleServerFinal` to completion has authenticated the server, and a
//! client that skips it has not. Both proofs are over the same `AuthMessage`,
//! which covers every byte of the first three messages, so neither end can
//! have its parameters rewritten in flight without the other noticing.
//!
//! What the exchange cannot do on its own is tell whether the transport
//! underneath it is the one the peer thinks it is. That is what channel
//! binding adds, and why `-PLUS` exists; see `messages.ChannelBinding`.
//!
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
//! [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677

const std = @import("std");
const Io = std.Io;

const messages = @import("messages.zig");
const saslprep = @import("saslprep.zig");

const Allocator = std.mem.Allocator;
const b64 = std.base64.standard;

/// How to prepare a password, or a username, before it goes into the key
/// schedule or onto the wire.
pub const Normalization = enum {
    /// Apply SASLprep (RFC 4013), falling back to the raw bytes if it fails.
    /// This is what PostgreSQL does, and what reproduces its verifier for any
    /// password. RFC 5802 says a client that cannot prepare a password should
    /// fail instead; PostgreSQL's fallback wins here because the point is to
    /// agree with the peer, and every peer worth agreeing with does this.
    saslprep,

    /// Use the bytes as given. Correct only if the caller has already
    /// prepared them, or knows they are pure ASCII — on which SASLprep is the
    /// identity anyway.
    raw,
};

/// The SASL mechanism name for a hash, per RFC 5802 section 4: `SCRAM-`
/// followed by the hash's name from IANA's "Hash Function Textual Names"
/// registry.
///
/// Anything not listed is a compile error rather than a guess, because a
/// mechanism name is what the two ends use to agree on which mechanism they
/// are running — inventing one produces a client that negotiates something no
/// server has heard of.
fn mechanismName(comptime Hash: type) []const u8 {
    const sha2 = std.crypto.hash.sha2;
    const sha3 = std.crypto.hash.sha3;
    // SCRAM-SHA-1 is RFC 5802's own instantiation and SCRAM-SHA-256 is RFC
    // 7677. The rest of the SHA-2 names need no document of their own: section
    // 4 builds a mechanism name by prefixing `SCRAM-` to an entry in IANA's
    // "Hash Function Textual Names" registry, and that registry holds sha-1,
    // sha-224, sha-256, sha-384 and sha-512 and nothing else.
    //
    // SHA-3 is the exception, precisely because it is not in that registry:
    // its name cannot be derived and has to be specified, which
    // draft-melnikov-scram-sha3-512 does. (There is a matching draft for
    // SCRAM-SHA-512, but that name follows from the registry regardless.)
    if (Hash == std.crypto.hash.Sha1) return "SCRAM-SHA-1";
    if (Hash == sha2.Sha224) return "SCRAM-SHA-224";
    if (Hash == sha2.Sha256) return "SCRAM-SHA-256";
    if (Hash == sha2.Sha384) return "SCRAM-SHA-384";
    if (Hash == sha2.Sha512) return "SCRAM-SHA-512";
    if (Hash == sha3.Sha3_512) return "SCRAM-SHA3-512";
    @compileError("no registered SCRAM mechanism name for " ++ @typeName(Hash));
}

pub fn Mechanism(comptime H: type) type {
    return struct {
        /// The hash this mechanism is built on.
        pub const Hash = H;

        /// The HMAC built on this mechanism's hash. `HMAC(k, m)` throughout
        /// RFC 5802 means this.
        pub const Hmac = std.crypto.auth.hmac.Hmac(Hash);

        /// Length of SaltedPassword, ClientKey, StoredKey and ServerKey. They
        /// are all one hash output wide.
        pub const key_length = Hash.digest_length;

        /// The SASL mechanism name, e.g. `SCRAM-SHA-256`.
        pub const name = mechanismName(Hash);

        /// The channel-binding variant of the name, e.g.
        /// `SCRAM-SHA-256-PLUS`. A client sends `p=` only under this name.
        pub const plus_name = name ++ "-PLUS";

        /// The mechanism tag of a stored verifier, including the separator
        /// that follows it. For SHA-256 this is exactly the prefix PostgreSQL
        /// writes into `pg_authid.rolpassword`.
        pub const prefix = name ++ "$";

        /// PostgreSQL's built-in default (`SCRAM_DEFAULT_ITERATIONS`, also the
        /// default of the `scram_iterations` GUC added in PostgreSQL 16), and
        /// the floor RFC 7677 section 4 recommends.
        pub const default_iterations: u32 = 4096;

        /// PostgreSQL's `SCRAM_DEFAULT_SALT_LEN`.
        pub const default_salt_length: usize = 16;

        /// Longest salt this module will store. PostgreSQL generates 16-byte
        /// salts; the extra room is only so that verifiers produced elsewhere
        /// still parse.
        pub const max_salt_length: usize = messages.max_salt_length;

        /// Upper bound on the length of an encoded verifier, for sizing stack
        /// buffers.
        pub const max_encoded_length = prefix.len +
            10 + // decimal digits of a u32
            1 + b64.Encoder.calcSize(max_salt_length) +
            1 + b64.Encoder.calcSize(key_length) +
            1 + b64.Encoder.calcSize(key_length);

        /// What the key schedule itself can reject. It does no I/O and no
        /// allocation, so these are the only ways it can fail.
        pub const DeriveError = error{
            /// `iterations` was zero.
            InvalidIterationCount,
            /// The salt was empty.
            SaltTooShort,
            /// The salt was longer than `max_salt_length`.
            SaltTooLong,
        };

        pub const Error = DeriveError || Allocator.Error;

        pub const ParseError = error{
            /// The text does not start with `prefix`.
            UnsupportedMechanism,
            /// The `<iterations>:<salt>$<stored>:<server>` shape is wrong.
            MalformedVerifier,
            /// The iteration count is not a decimal number that fits in a u32.
            InvalidIterationCount,
            /// A base64 field would not decode.
            InvalidBase64,
            /// The salt was empty or longer than `max_salt_length`.
            SaltTooShort,
            SaltTooLong,
            /// StoredKey or ServerKey was not `key_length` bytes.
            InvalidKeyLength,
        };

        /// Options for `generate`. Named for what it configures rather than
        /// simply `Options`, because `Client` has options of its own and a
        /// nested declaration that shadows its container's is ambiguous at
        /// every use inside it.
        pub const GenerateOptions = struct {
            /// PBKDF2 rounds. Must be at least 1; PostgreSQL uses
            /// `default_iterations`.
            iterations: u32 = default_iterations,
            /// Number of random salt bytes to draw. Must be in
            /// `1..=max_salt_length`.
            salt_length: usize = default_salt_length,
            normalization: Normalization = .saslprep,
        };

        /// The three keys a password and salt derive to. `client_key` is the
        /// one a server must never store.
        pub const Keys = struct {
            client_key: [key_length]u8,
            stored_key: [key_length]u8,
            server_key: [key_length]u8,

            /// Overwrites all three. `client_key` is the secret worth wiping;
            /// the other two are wiped with it so that no caller has to
            /// remember which is which.
            pub fn deinit(self: *Keys) void {
                std.crypto.secureZero(u8, &self.client_key);
                std.crypto.secureZero(u8, &self.stored_key);
                std.crypto.secureZero(u8, &self.server_key);
            }
        };

        /// Runs the key schedule over an already-prepared password.
        ///
        /// `prepared` must have been through SASLprep already — this is the
        /// layer below `compute`, exposed because a client that has the
        /// password in hand should prepare it once rather than once per
        /// derivation.
        pub fn deriveKeys(prepared: []const u8, salt: []const u8, iterations: u32) DeriveError!Keys {
            if (iterations < 1) return error.InvalidIterationCount;
            if (salt.len == 0) return error.SaltTooShort;
            if (salt.len > max_salt_length) return error.SaltTooLong;

            // dk is exactly one PRF block, so pbkdf2 can only fail on
            // rounds == 0, which is already ruled out above.
            var salted_password: [key_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &salted_password);
            std.crypto.pwhash.pbkdf2(&salted_password, prepared, salt, iterations, Hmac) catch
                unreachable;

            var keys: Keys = undefined;
            Hmac.create(&keys.client_key, "Client Key", &salted_password);
            Hash.hash(&keys.client_key, &keys.stored_key, .{});
            Hmac.create(&keys.server_key, "Server Key", &salted_password);
            return keys;
        }

        /// A parsed or freshly derived verifier. Contains no secret material:
        /// the plaintext cannot be recovered from it, though it is still
        /// enough to impersonate the server to a client, so treat it as
        /// sensitive.
        pub const Secret = struct {
            iterations: u32,
            salt_buf: [max_salt_length]u8,
            salt_len: u8,
            stored_key: [key_length]u8,
            server_key: [key_length]u8,

            pub fn salt(self: *const Secret) []const u8 {
                return self.salt_buf[0..self.salt_len];
            }

            /// Renders the verifier. Use the `{f}` placeholder:
            /// `try writer.print("{f}", .{secret})`.
            pub fn format(self: Secret, w: *Io.Writer) Io.Writer.Error!void {
                // One scratch buffer per field: `encode` returns a slice into
                // the buffer it was handed, so sharing one across a single
                // `print` would let the last call clobber the earlier ones.
                var salt_buf: [b64.Encoder.calcSize(max_salt_length)]u8 = undefined;
                var stored_buf: [b64.Encoder.calcSize(key_length)]u8 = undefined;
                var server_buf: [b64.Encoder.calcSize(key_length)]u8 = undefined;
                try w.print("{s}{d}:{s}${s}:{s}", .{
                    prefix,
                    self.iterations,
                    b64.Encoder.encode(&salt_buf, self.salt()),
                    b64.Encoder.encode(&stored_buf, &self.stored_key),
                    b64.Encoder.encode(&server_buf, &self.server_key),
                });
            }

            /// Writes the verifier into `buf`, which must be at least
            /// `max_encoded_length` bytes to be safe for any input.
            pub fn bufPrint(self: *const Secret, buf: []u8) error{NoSpaceLeft}![]const u8 {
                return std.fmt.bufPrint(buf, "{f}", .{self.*});
            }

            /// Caller owns the returned memory.
            pub fn toOwnedString(self: *const Secret, gpa: Allocator) ![]u8 {
                return std.fmt.allocPrint(gpa, "{f}", .{self.*});
            }

            /// Reads a verifier back out of `rolpassword` form.
            pub fn parse(text: []const u8) ParseError!Secret {
                if (!std.mem.startsWith(u8, text, prefix)) return error.UnsupportedMechanism;
                const body = text[prefix.len..];

                const dollar = std.mem.findScalar(u8, body, '$') orelse
                    return error.MalformedVerifier;
                const params = body[0..dollar];
                const keys = body[dollar + 1 ..];

                const colon = std.mem.findScalar(u8, params, ':') orelse
                    return error.MalformedVerifier;
                const iterations = std.fmt.parseInt(u32, params[0..colon], 10) catch
                    return error.InvalidIterationCount;
                if (iterations < 1) return error.InvalidIterationCount;

                const key_colon = std.mem.findScalar(u8, keys, ':') orelse
                    return error.MalformedVerifier;

                var self: Secret = undefined;
                self.iterations = iterations;

                const salt_len = b64.Decoder.calcSizeForSlice(params[colon + 1 ..]) catch
                    return error.InvalidBase64;
                if (salt_len == 0) return error.SaltTooShort;
                if (salt_len > max_salt_length) return error.SaltTooLong;
                b64.Decoder.decode(self.salt_buf[0..salt_len], params[colon + 1 ..]) catch
                    return error.InvalidBase64;
                @memset(self.salt_buf[salt_len..], 0);
                self.salt_len = @intCast(salt_len);

                try decodeKey(&self.stored_key, keys[0..key_colon]);
                try decodeKey(&self.server_key, keys[key_colon + 1 ..]);
                return self;
            }

            /// Recomputes the verifier from `password` using this secret's
            /// salt and iteration count and compares in constant time.
            pub fn verify(
                self: *const Secret,
                gpa: Allocator,
                password: []const u8,
                normalization: Normalization,
            ) Error!bool {
                const candidate = try compute(
                    gpa,
                    password,
                    self.salt(),
                    self.iterations,
                    normalization,
                );
                return std.crypto.timing_safe.eql(
                    [key_length]u8,
                    candidate.stored_key,
                    self.stored_key,
                ) and std.crypto.timing_safe.eql(
                    [key_length]u8,
                    candidate.server_key,
                    self.server_key,
                );
            }

            pub fn eql(a: *const Secret, b: *const Secret) bool {
                return a.iterations == b.iterations and
                    std.mem.eql(u8, a.salt(), b.salt()) and
                    std.crypto.timing_safe.eql([key_length]u8, a.stored_key, b.stored_key) and
                    std.crypto.timing_safe.eql([key_length]u8, a.server_key, b.server_key);
            }
        };

        fn decodeKey(dest: *[key_length]u8, text: []const u8) ParseError!void {
            const len = b64.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
            if (len != key_length) return error.InvalidKeyLength;
            b64.Decoder.decode(dest, text) catch return error.InvalidBase64;
        }

        /// Derives a verifier from `password` and a caller-supplied salt.
        /// Deterministic — use this to reproduce an existing verifier or in
        /// tests; use `generate` for new passwords.
        ///
        /// `gpa` is only touched when SASLprep has real work to do, which
        /// means never for an all-ASCII password or for `.raw`.
        pub fn compute(
            gpa: Allocator,
            password: []const u8,
            salt: []const u8,
            iterations: u32,
            normalization: Normalization,
        ) Error!Secret {
            if (iterations < 1) return error.InvalidIterationCount;
            if (salt.len == 0) return error.SaltTooShort;
            if (salt.len > max_salt_length) return error.SaltTooLong;

            const prepared = try prepare(gpa, password, normalization);
            defer prepared.deinit(gpa);

            var keys = try deriveKeys(prepared.bytes, salt, iterations);
            defer keys.deinit();

            var self: Secret = undefined;
            self.iterations = iterations;
            @memcpy(self.salt_buf[0..salt.len], salt);
            @memset(self.salt_buf[salt.len..], 0);
            self.salt_len = @intCast(salt.len);
            self.stored_key = keys.stored_key;
            self.server_key = keys.server_key;
            return self;
        }

        /// Derives a verifier from `password` with a fresh random salt drawn
        /// from `io`. This is the entry point for enrolling a new password.
        pub fn generate(
            gpa: Allocator,
            io: Io,
            password: []const u8,
            options: GenerateOptions,
        ) Error!Secret {
            if (options.salt_length == 0) return error.SaltTooShort;
            if (options.salt_length > max_salt_length) return error.SaltTooLong;

            var salt: [max_salt_length]u8 = undefined;
            io.random(salt[0..options.salt_length]);
            return compute(
                gpa,
                password,
                salt[0..options.salt_length],
                options.iterations,
                options.normalization,
            );
        }

        /// The client half of the exchange: a state machine driven by the
        /// caller's transport, which this module never touches.
        ///
        ///     var client: Client = try .init(gpa, io, .{
        ///         .username = "user",
        ///         .password = "pencil",
        ///     });
        ///     defer client.deinit();
        ///
        ///     try conn.send(client.clientFirst());
        ///     try client.handleServerFirst(try conn.receive());
        ///     try conn.send(try client.clientFinal());
        ///     try client.handleServerFinal(try conn.receive());
        ///     // Past here both ends have proved themselves.
        ///
        /// Every slice handed back is owned by the `Client` and stays valid
        /// until `deinit`; every slice passed in is copied if it is needed
        /// later, so the caller's buffers can be reused immediately.
        pub const Client = struct {
            gpa: Allocator,
            state: State,

            /// SASLprep'd, owned, and wiped by `deinit`. Needed only until
            /// the server sends the salt, and freed there.
            password: ?[]u8,
            normalization: Normalization,
            minimum_iterations: u32,

            /// `gs2-header client-first-message-bare`, owned.
            first: []const u8,
            /// How much of `first` is the GS2 header, which is also the front
            /// of the channel-binding input.
            gs2_header_len: usize,

            /// Owned copies, because the caller's may not outlive the call.
            channel_binding: messages.ChannelBinding,

            /// `AuthMessage`, accumulated across the exchange.
            auth_message: std.ArrayList(u8),
            /// How much of the tail of `first` is the client nonce.
            client_nonce_len: usize,
            /// The combined nonce from the server's first message, owned.
            nonce: []const u8,
            /// `client-final-message`, owned, built by `clientFinal`.
            final: []const u8,

            keys: Keys,
            server_signature: [key_length]u8,
            /// Set when the server answered with `e=`. The text is an owned
            /// copy: the message it was parsed out of belongs to the caller,
            /// who is free to reuse that buffer the moment the call returns.
            failure: ?messages.ServerFinal.Failure,

            const State = enum {
                /// `init` has run; `clientFirst` is ready.
                started,
                /// The server's first message has been accepted.
                challenged,
                /// `clientFinal` has been built and the proof sent.
                proved,
                /// The server proved itself too. The exchange succeeded.
                authenticated,
                /// Something failed. The client will not produce more
                /// messages.
                failed,
            };

            pub const InitError = error{
                /// A username or authorization identity contained a NUL,
                /// which no attribute value can carry.
                InvalidName,
                /// The channel-binding type is not a legal `cb-name`.
                InvalidChannelBindingType,
                /// An explicitly supplied nonce was empty or contained
                /// something outside the `printable` production.
                InvalidNonce,
                OutOfMemory,
            };

            pub const ServerFirstError = messages.ParseError || error{
                /// The server's nonce does not begin with the one we sent, so
                /// this is not a reply to our message.
                NonceMismatch,
                /// The server asked for fewer PBKDF2 rounds than
                /// `Options.minimum_iterations`.
                IterationCountTooLow,
                OutOfMemory,
            };

            pub const ServerFinalError = messages.ParseError || error{
                /// The server's `ServerSignature` did not match. It does not
                /// know `ServerKey`, so it is not the server that holds this
                /// user's verifier, whatever else it may have said.
                ServerSignatureMismatch,
                /// `ServerSignature` was not `key_length` bytes.
                InvalidKeyLength,
                /// The server answered `e=`. `serverError` says which.
                AuthenticationFailed,
            };

            pub const Options = struct {
                /// The authentication identity. May be empty: PostgreSQL
                /// sends `n=,` because libpq has already named the user in
                /// the startup packet, and the server takes it from there.
                username: []const u8,
                password: []const u8,
                /// The authorization identity, when it differs from the
                /// authentication identity — "log in as me, act as them".
                authzid: ?[]const u8 = null,
                /// What to tell the server about channel binding, and the
                /// binding itself when there is one. See
                /// `messages.ChannelBinding`: the variant is an assertion
                /// about what the server advertised, and the server checks it.
                channel_binding: messages.ChannelBinding = .none,
                normalization: Normalization = .saslprep,
                /// Random bytes to draw for the client nonce, which is sent
                /// as base64 of them. RFC 5802 sets no length; this is the
                /// 192 bits that PostgreSQL, Cyrus SASL and the Java
                /// implementations all land within a few bytes of.
                nonce_length: usize = 24,
                /// Use this nonce verbatim instead of drawing one. Only for
                /// reproducing published test vectors — a reused nonce
                /// destroys the guarantee the exchange exists to provide.
                nonce: ?[]const u8 = null,
                /// Refuse a server that asks for fewer rounds than this.
                /// RFC 7677 section 4 says the count should be at least 4096,
                /// and a server naming a low one is either misconfigured or
                /// trying to make an offline attack on the password cheaper.
                minimum_iterations: u32 = default_iterations,
            };

            pub fn init(gpa: Allocator, io: Io, options: Options) InitError!Client {
                if (!messages.validSaslName(options.username)) return error.InvalidName;
                if (options.authzid) |id| {
                    if (!messages.validSaslName(id)) return error.InvalidName;
                }
                switch (options.channel_binding) {
                    .bound => |binding| if (!messages.validChannelBindingName(binding.type))
                        return error.InvalidChannelBindingType,
                    .none, .unsupported_by_server => {},
                }

                var self: Client = .{
                    .gpa = gpa,
                    .state = .started,
                    .password = null,
                    .normalization = options.normalization,
                    .minimum_iterations = options.minimum_iterations,
                    .first = &.{},
                    .gs2_header_len = 0,
                    .client_nonce_len = 0,
                    .channel_binding = .none,
                    .auth_message = .empty,
                    .nonce = &.{},
                    .final = &.{},
                    .keys = undefined,
                    .server_signature = undefined,
                    .failure = null,
                };
                errdefer self.deinit();

                self.channel_binding = try cloneChannelBinding(gpa, options.channel_binding);

                // The password is prepared once, here, rather than when the
                // salt arrives: preparation can allocate, and doing it up
                // front keeps the failure away from the middle of a network
                // exchange.
                const prepared = try prepare(gpa, options.password, options.normalization);
                defer prepared.deinit(gpa);
                self.password = try gpa.dupe(u8, prepared.bytes);

                const nonce = if (options.nonce) |explicit| explicit else blk: {
                    // Base64 of random bytes: every character of the standard
                    // alphabet, padding included, is in `printable`.
                    const raw = try gpa.alloc(u8, options.nonce_length);
                    defer gpa.free(raw);
                    io.random(raw);
                    break :blk try encodeAlloc(gpa, raw);
                };
                defer if (options.nonce == null) gpa.free(nonce);
                if (!messages.validNonce(nonce)) return error.InvalidNonce;

                // The username and the authorization identity go through the
                // same preparation as the password: RFC 5802 section 5.1 says
                // a client should SASLprep them, and a server that prepared a
                // name on enrolment will not match one that did not.
                const user = try prepare(gpa, options.username, options.normalization);
                defer user.deinit(gpa);
                const authzid: ?saslprep.Prepared = if (options.authzid) |id|
                    try prepare(gpa, id, options.normalization)
                else
                    null;
                defer if (authzid) |id| id.deinit(gpa);

                var builder: Io.Writer.Allocating = .init(gpa);
                defer builder.deinit();
                const w = &builder.writer;
                messages.writeGs2Header(
                    w,
                    self.channel_binding,
                    if (authzid) |id| id.bytes else null,
                ) catch return error.OutOfMemory;
                const header_len = builder.written().len;
                w.writeAll("n=") catch return error.OutOfMemory;
                messages.writeSaslName(w, user.bytes) catch return error.OutOfMemory;
                w.print(",r={s}", .{nonce}) catch return error.OutOfMemory;

                self.gs2_header_len = header_len;
                self.client_nonce_len = nonce.len;
                self.first = try gpa.dupe(u8, builder.written());

                // `AuthMessage` starts at the bare message — the GS2 header is
                // deliberately excluded here and re-enters through the `c=`
                // attribute of the final message, which is what lets a server
                // detect a rewritten channel-binding flag.
                try self.auth_message.appendSlice(gpa, self.first[header_len..]);
                return self;
            }

            pub fn deinit(self: *Client) void {
                if (self.password) |password| {
                    std.crypto.secureZero(u8, password);
                    self.gpa.free(password);
                }
                self.keys.deinit();
                std.crypto.secureZero(u8, &self.server_signature);
                freeChannelBinding(self.gpa, self.channel_binding);
                if (self.failure) |failure| self.gpa.free(failure.text);
                self.auth_message.deinit(self.gpa);
                self.gpa.free(self.first);
                self.gpa.free(self.nonce);
                self.gpa.free(self.final);
                self.* = undefined;
            }

            /// The mechanism to negotiate for this exchange: `plus_name` when
            /// channel binding is in use, `name` otherwise. Sending the wrong
            /// one is what the server's downgrade check is looking for.
            pub fn mechanism(self: *const Client) []const u8 {
                return if (self.channel_binding.wantsPlus()) plus_name else name;
            }

            /// `client-first-message`. Valid until `deinit`.
            pub fn clientFirst(self: *const Client) []const u8 {
                std.debug.assert(self.state == .started);
                return self.first;
            }

            /// Accepts `server-first-message` and runs the key schedule over
            /// the salt and iteration count in it.
            ///
            /// This is where the PBKDF2 work happens, so it is the expensive
            /// call — `minimum_iterations` bounds it from below, but nothing
            /// bounds it from above except the `u32` the server sent, and a
            /// hostile server can make this take arbitrarily long. A caller
            /// that cannot afford that should bound the count itself before
            /// reaching this.
            pub fn handleServerFirst(
                self: *Client,
                message: []const u8,
            ) ServerFirstError!void {
                std.debug.assert(self.state == .started);
                errdefer self.state = .failed;

                const parsed = try messages.ServerFirst.parse(message);

                // The server's nonce must extend ours. Without this check a
                // reply from one exchange could be spliced into another.
                const client_nonce = self.clientNonce();
                if (!std.mem.startsWith(u8, parsed.nonce, client_nonce) or
                    parsed.nonce.len == client_nonce.len)
                {
                    return error.NonceMismatch;
                }

                if (parsed.iterations < self.minimum_iterations) return error.IterationCountTooLow;

                const nonce = try self.gpa.dupe(u8, parsed.nonce);
                errdefer self.gpa.free(nonce);

                try self.auth_message.append(self.gpa, ',');
                try self.auth_message.appendSlice(self.gpa, message);

                // The salt and the iteration count both came out of a parser
                // that already enforces exactly the bounds `deriveKeys`
                // checks, so it has no way left to fail.
                const password = self.password.?;
                self.keys = deriveKeys(password, parsed.salt(), parsed.iterations) catch
                    unreachable;

                // The password has done its work; nothing later in the
                // exchange needs it.
                std.crypto.secureZero(u8, password);
                self.gpa.free(password);
                self.password = null;

                self.nonce = nonce;
                self.state = .challenged;
            }

            /// Builds `client-final-message`, including the proof. Valid
            /// until `deinit`.
            pub fn clientFinal(self: *Client) Allocator.Error![]const u8 {
                std.debug.assert(self.state == .challenged);
                errdefer self.state = .failed;

                var builder: Io.Writer.Allocating = .init(self.gpa);
                defer builder.deinit();
                const w = &builder.writer;

                // `cbind-input = gs2-header [ cbind-data ]`. Repeating the
                // header here, inside something the proof covers, is what
                // makes the flag at the front of the first message
                // unforgeable.
                const header = self.first[0..self.gs2_header_len];
                const cbind_data = switch (self.channel_binding) {
                    .bound => |binding| binding.data,
                    .none, .unsupported_by_server => "",
                };
                const cbind_input = try std.mem.concat(self.gpa, u8, &.{ header, cbind_data });
                defer self.gpa.free(cbind_input);

                const cbind_b64 = try encodeAlloc(self.gpa, cbind_input);
                defer self.gpa.free(cbind_b64);

                w.print("c={s},r={s}", .{ cbind_b64, self.nonce }) catch
                    return error.OutOfMemory;

                // `AuthMessage = client-first-bare + "," + server-first + ","
                //              + client-final-without-proof`
                try self.auth_message.append(self.gpa, ',');
                try self.auth_message.appendSlice(self.gpa, builder.written());
                const auth_message = self.auth_message.items;

                var client_signature: [key_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &client_signature);
                Hmac.create(&client_signature, auth_message, &self.keys.stored_key);

                var proof: [key_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &proof);
                for (&proof, self.keys.client_key, client_signature) |*p, k, s| p.* = k ^ s;

                var proof_b64: [b64.Encoder.calcSize(key_length)]u8 = undefined;
                w.print(",p={s}", .{b64.Encoder.encode(&proof_b64, &proof)}) catch
                    return error.OutOfMemory;

                // The server's half of the mutual authentication is over the
                // same message, so it can be computed now and compared when
                // the reply arrives.
                Hmac.create(&self.server_signature, auth_message, &self.keys.server_key);

                // Both proofs are computed; nothing after this needs the
                // keys, and `ClientKey` in particular is the one piece of
                // material here that would let a thief log in as the user.
                self.keys.deinit();

                self.final = try self.gpa.dupe(u8, builder.written());
                self.state = .proved;
                return self.final;
            }

            /// Accepts `server-final-message` and checks the server's proof.
            ///
            /// Returning without error is the only thing that authenticates
            /// the server. A client that sends its proof and then treats the
            /// connection as authenticated without getting here has proved
            /// itself to an unknown peer and learned nothing in return.
            pub fn handleServerFinal(
                self: *Client,
                message: []const u8,
            ) ServerFinalError!void {
                std.debug.assert(self.state == .proved);
                errdefer self.state = .failed;

                switch (try messages.ServerFinal.parse(message)) {
                    .failure => |failure| {
                        // Losing the copy to an allocation failure costs
                        // the text of a diagnostic, not the diagnosis: the
                        // parsed `value` is still there, and the exchange has
                        // failed either way. Reporting `OutOfMemory` here
                        // instead would replace the real answer with a
                        // less useful one.
                        self.failure = .{
                            .value = failure.value,
                            .text = self.gpa.dupe(u8, failure.text) catch "",
                        };
                        return error.AuthenticationFailed;
                    },
                    .verifier => |verifier| {
                        var signature: [key_length]u8 = undefined;
                        const len = b64.Decoder.calcSizeForSlice(verifier) catch
                            return error.InvalidBase64;
                        if (len != key_length) return error.InvalidKeyLength;
                        b64.Decoder.decode(&signature, verifier) catch
                            return error.InvalidBase64;

                        if (!std.crypto.timing_safe.eql(
                            [key_length]u8,
                            signature,
                            self.server_signature,
                        )) return error.ServerSignatureMismatch;
                    },
                }

                self.state = .authenticated;
            }

            /// The error the server sent with `e=`, if it sent one. Only
            /// meaningful after `handleServerFinal` returned
            /// `error.AuthenticationFailed`; a server is free to fail without
            /// saying why, or to lie, so this is for logs rather than for
            /// control flow.
            pub fn serverError(self: *const Client) ?messages.ServerFinal.Failure {
                return self.failure;
            }

            /// Whether the exchange completed and the server proved itself.
            pub fn authenticated(self: *const Client) bool {
                return self.state == .authenticated;
            }

            /// The nonce this client generated, which is the front of the
            /// combined nonce the server must echo. It is the tail of the
            /// first message, since `r=` is the last attribute there.
            fn clientNonce(self: *const Client) []const u8 {
                return self.first[self.first.len - self.client_nonce_len ..];
            }
        };
    };
}

/// SASLprep, or not, depending on `normalization`. The result may alias
/// `input`, so `input` has to outlive it.
fn prepare(
    gpa: Allocator,
    input: []const u8,
    normalization: Normalization,
) Allocator.Error!saslprep.Prepared {
    return switch (normalization) {
        .saslprep => saslprep.prepOrRaw(gpa, input),
        .raw => .{ .bytes = input, .owned = false },
    };
}

fn encodeAlloc(gpa: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, b64.Encoder.calcSize(bytes.len));
    std.debug.assert(b64.Encoder.encode(out, bytes).len == out.len);
    return out;
}

fn cloneChannelBinding(
    gpa: Allocator,
    binding: messages.ChannelBinding,
) Allocator.Error!messages.ChannelBinding {
    return switch (binding) {
        .none => .none,
        .unsupported_by_server => .unsupported_by_server,
        .bound => |data| blk: {
            const @"type" = try gpa.dupe(u8, data.type);
            errdefer gpa.free(@"type");
            break :blk .{ .bound = .{
                .type = @"type",
                .data = try gpa.dupe(u8, data.data),
            } };
        },
    };
}

fn freeChannelBinding(gpa: Allocator, binding: messages.ChannelBinding) void {
    switch (binding) {
        .none, .unsupported_by_server => {},
        .bound => |data| {
            gpa.free(data.type);
            gpa.free(data.data);
        },
    }
}

// ---------------------------------------------------------------------------

const testing = std.testing;

/// RFC 7677 section 3.
const Sha256Scram = Mechanism(std.crypto.hash.sha2.Sha256);
/// RFC 5802 section 5.
const Sha1Scram = Mechanism(std.crypto.hash.Sha1);

test "mechanism names" {
    try testing.expectEqualStrings("SCRAM-SHA-256", Sha256Scram.name);
    try testing.expectEqualStrings("SCRAM-SHA-256-PLUS", Sha256Scram.plus_name);
    try testing.expectEqualStrings("SCRAM-SHA-256$", Sha256Scram.prefix);
    try testing.expectEqualStrings("SCRAM-SHA-1", Sha1Scram.name);
    try testing.expectEqualStrings("SCRAM-SHA-1-PLUS", Sha1Scram.plus_name);
    try testing.expectEqual(@as(usize, 32), Sha256Scram.key_length);
    try testing.expectEqual(@as(usize, 20), Sha1Scram.key_length);
}

/// Drives a client through the whole exchange against a transcript, checking
/// that it produces exactly the messages the RFC published.
///
/// The two vectors differ only in the hash, which is the claim `Mechanism`
/// makes and the reason this is written once.
fn expectTranscript(
    comptime Scram: type,
    username: []const u8,
    password: []const u8,
    nonce: []const u8,
    client_first: []const u8,
    server_first: []const u8,
    client_final: []const u8,
    server_final: []const u8,
) !void {
    var client: Scram.Client = try .init(testing.allocator, testing.io, .{
        .username = username,
        .password = password,
        .nonce = nonce,
    });
    defer client.deinit();

    try testing.expectEqualStrings(Scram.name, client.mechanism());
    try testing.expectEqualStrings(client_first, client.clientFirst());

    try client.handleServerFirst(server_first);
    try testing.expectEqualStrings(client_final, try client.clientFinal());

    try testing.expect(!client.authenticated());
    try client.handleServerFinal(server_final);
    try testing.expect(client.authenticated());
}

test "RFC 7677 section 3 exchange" {
    try expectTranscript(
        Sha256Scram,
        "user",
        "pencil",
        "rOprNGfwEbeRWgbNEkqO",
        "n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
            "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
        "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
            "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
    );
}

test "RFC 5802 section 5 exchange" {
    try expectTranscript(
        Sha1Scram,
        "user",
        "pencil",
        "fyko+d2lbbFgONRv9qkxdawL",
        "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
        "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
        "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," ++
            "p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
        "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=",
    );
}

/// Verifies a `ClientProof` the way a server does, from nothing but a stored
/// verifier: recover `ClientKey` by undoing the XOR, hash it, and see whether
/// it is the `StoredKey` on file.
///
/// This is the other half of the protocol, written here rather than in the
/// library because the library is a client. It exists so the tests below check
/// the proof against something derived independently of the code that built
/// it, instead of against itself.
fn serverVerifiesProof(
    comptime Scram: type,
    secret: *const Scram.Secret,
    auth_message: []const u8,
    proof_b64: []const u8,
) !bool {
    var proof: [Scram.key_length]u8 = undefined;
    try b64.Decoder.decode(&proof, proof_b64);

    var client_signature: [Scram.key_length]u8 = undefined;
    Scram.Hmac.create(&client_signature, auth_message, &secret.stored_key);

    var client_key: [Scram.key_length]u8 = undefined;
    for (&client_key, proof, client_signature) |*k, p, sig| k.* = p ^ sig;

    var stored_key: [Scram.key_length]u8 = undefined;
    Scram.Hash.hash(&client_key, &stored_key, .{});
    return std.crypto.timing_safe.eql([Scram.key_length]u8, stored_key, secret.stored_key);
}

/// The attributes of a message, as a lookup rather than an ordered walk, so a
/// test can pull one field out without restating the grammar.
fn attribute(message: []const u8, name: u8) ![]const u8 {
    var attrs: messages.Attributes = .init(message);
    while (try attrs.next()) |attr| {
        if (attr.name == name) return attr.value;
    }
    return error.TestUnexpectedResult;
}

test "the proof verifies against a stored verifier" {
    const gpa = testing.allocator;
    const Scram = Sha256Scram;

    var salt: [16]u8 = undefined;
    try b64.Decoder.decode(&salt, "W22ZaJ0SNY7soEsUEjb6gQ==");
    const secret = try Scram.compute(gpa, "pencil", &salt, 4096, .saslprep);

    var client: Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "rOprNGfwEbeRWgbNEkqO",
    });
    defer client.deinit();

    const server_first = "r=rOprNGfwEbeRWgbNEkqO-server,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    try client.handleServerFirst(server_first);
    const final = try client.clientFinal();

    // `AuthMessage` as the server reassembles it: the client's first message
    // without its GS2 header, its own message, and the client's final message
    // with the proof cut off.
    const bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
    const proof_at = std.mem.findLast(u8, final, ",p=").?;
    var buf: [512]u8 = undefined;
    const auth_message = try std.fmt.bufPrint(&buf, "{s},{s},{s}", .{
        bare,
        server_first,
        final[0..proof_at],
    });

    try testing.expect(try serverVerifiesProof(
        Scram,
        &secret,
        auth_message,
        try attribute(final, 'p'),
    ));

    // And the wrong password does not.
    const other = try Scram.compute(gpa, "pencil2", &salt, 4096, .saslprep);
    try testing.expect(!try serverVerifiesProof(
        Scram,
        &other,
        auth_message,
        try attribute(final, 'p'),
    ));

    // Finish the exchange with the signature the server would send back.
    var server_signature: [Scram.key_length]u8 = undefined;
    Scram.Hmac.create(&server_signature, auth_message, &secret.server_key);
    var encoded: [b64.Encoder.calcSize(Scram.key_length)]u8 = undefined;
    var reply: [128]u8 = undefined;
    try client.handleServerFinal(try std.fmt.bufPrint(&reply, "v={s}", .{
        b64.Encoder.encode(&encoded, &server_signature),
    }));
    try testing.expect(client.authenticated());
}

test "channel binding" {
    const gpa = testing.allocator;
    const server_first = "r=nonce-server,s=YWJj,i=4096";

    // `n`: no support. The channel-binding input is the header alone.
    {
        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "user",
            .password = "pencil",
            .nonce = "nonce",
            .channel_binding = .none,
        });
        defer client.deinit();
        try testing.expectEqualStrings("SCRAM-SHA-256", client.mechanism());
        try testing.expectEqualStrings("n,,n=user,r=nonce", client.clientFirst());
        try client.handleServerFirst(server_first);
        try testing.expectEqualStrings("biws", try attribute(try client.clientFinal(), 'c'));
    }

    // `y`: the client supports it but saw no -PLUS mechanism advertised. The
    // flag still travels inside the proof, so a server that did advertise one
    // will see the downgrade.
    {
        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "user",
            .password = "pencil",
            .nonce = "nonce",
            .channel_binding = .unsupported_by_server,
        });
        defer client.deinit();
        try testing.expectEqualStrings("SCRAM-SHA-256", client.mechanism());
        try testing.expectEqualStrings("y,,n=user,r=nonce", client.clientFirst());
        try client.handleServerFirst(server_first);
        try testing.expectEqualStrings("eSws", try attribute(try client.clientFinal(), 'c'));
    }

    // `p`: bound. `c=` is base64 of the header followed by the binding data,
    // and the mechanism to negotiate is the -PLUS one.
    {
        var binding: [32]u8 = undefined;
        for (&binding, 0..) |*b, i| b.* = @intCast(i);

        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "user",
            .password = "pencil",
            .nonce = "nonce",
            .channel_binding = .{ .bound = .{
                .type = "tls-server-end-point",
                .data = &binding,
            } },
        });
        defer client.deinit();
        try testing.expectEqualStrings("SCRAM-SHA-256-PLUS", client.mechanism());
        try testing.expectEqualStrings(
            "p=tls-server-end-point,,n=user,r=nonce",
            client.clientFirst(),
        );
        try client.handleServerFirst(server_first);
        try testing.expectEqualStrings(
            "cD10bHMtc2VydmVyLWVuZC1wb2ludCwsAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            try attribute(try client.clientFinal(), 'c'),
        );
    }

    // Binding changes the proof: the same password and nonces against a
    // different channel produce a different `p=`.
    {
        var proofs: [2][]const u8 = undefined;
        for (&proofs, [_][]const u8{ "channel-one", "channel-two" }) |*slot, data| {
            var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
                .username = "user",
                .password = "pencil",
                .nonce = "nonce",
                .channel_binding = .{ .bound = .{ .type = "tls-exporter", .data = data } },
            });
            defer client.deinit();
            try client.handleServerFirst(server_first);
            slot.* = try gpa.dupe(u8, try attribute(try client.clientFinal(), 'p'));
        }
        defer for (proofs) |p| gpa.free(p);
        try testing.expect(!std.mem.eql(u8, proofs[0], proofs[1]));
    }
}

test "authorization identity" {
    var client: Sha256Scram.Client = try .init(testing.allocator, testing.io, .{
        .username = "user",
        .password = "pencil",
        .authzid = "admin",
        .nonce = "nonce",
    });
    defer client.deinit();
    try testing.expectEqualStrings("n,a=admin,n=user,r=nonce", client.clientFirst());
}

test "names are escaped and prepared" {
    const gpa = testing.allocator;

    // A comma and an equals sign in a username are escaped rather than
    // ending the attribute.
    {
        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "a,b=c",
            .password = "pencil",
            .nonce = "nonce",
        });
        defer client.deinit();
        try testing.expectEqualStrings("n,,n=a=2Cb=3Dc,r=nonce", client.clientFirst());
    }

    // SASLprep runs over the username too, so U+2168 is sent as "IX".
    {
        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "\u{2168}",
            .password = "pencil",
            .nonce = "nonce",
        });
        defer client.deinit();
        try testing.expectEqualStrings("n,,n=IX,r=nonce", client.clientFirst());
    }

    // PostgreSQL sends an empty username, because libpq has already named the
    // user in the startup packet.
    {
        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "",
            .password = "pencil",
            .nonce = "nonce",
        });
        defer client.deinit();
        try testing.expectEqualStrings("n,,n=,r=nonce", client.clientFirst());
    }
}

test "init rejects what cannot be sent" {
    const gpa = testing.allocator;
    const ok: Sha256Scram.Client.Options = .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    };

    var name = ok;
    name.username = "a\x00b";
    try testing.expectError(error.InvalidName, Sha256Scram.Client.init(gpa, testing.io, name));

    var authzid = ok;
    authzid.authzid = "a\x00b";
    try testing.expectError(error.InvalidName, Sha256Scram.Client.init(gpa, testing.io, authzid));

    var cb = ok;
    cb.channel_binding = .{ .bound = .{ .type = "tls unique", .data = "" } };
    try testing.expectError(
        error.InvalidChannelBindingType,
        Sha256Scram.Client.init(gpa, testing.io, cb),
    );

    for ([_][]const u8{ "", "has,comma", "has space" }) |bad| {
        var nonce = ok;
        nonce.nonce = bad;
        try testing.expectError(
            error.InvalidNonce,
            Sha256Scram.Client.init(gpa, testing.io, nonce),
        );
    }
}

test "the server's nonce has to extend ours" {
    const gpa = testing.allocator;
    for ([_][]const u8{
        "r=different-server,s=YWJj,i=4096", // not ours at all
        "r=nonce,s=YWJj,i=4096", // ours, with nothing added
        "r=nonc,s=YWJj,i=4096", // a prefix of ours
    }) |server_first| {
        var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
            .username = "user",
            .password = "pencil",
            .nonce = "nonce",
        });
        defer client.deinit();
        try testing.expectError(error.NonceMismatch, client.handleServerFirst(server_first));
        try testing.expect(!client.authenticated());
    }
}

test "a server asking for too few rounds is refused" {
    const gpa = testing.allocator;

    var strict: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    });
    defer strict.deinit();
    try testing.expectError(
        error.IterationCountTooLow,
        strict.handleServerFirst("r=nonce-server,s=YWJj,i=4095"),
    );

    // The floor is the client's to set: a peer that genuinely uses fewer is
    // reachable by lowering it deliberately.
    var lenient: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
        .minimum_iterations = 1,
    });
    defer lenient.deinit();
    try lenient.handleServerFirst("r=nonce-server,s=YWJj,i=1");
}

test "a server that cannot prove itself is not authenticated" {
    const gpa = testing.allocator;

    var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "rOprNGfwEbeRWgbNEkqO",
    });
    defer client.deinit();
    try client.handleServerFirst(
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
            "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
    );
    _ = try client.clientFinal();

    // The right length, the wrong value.
    try testing.expectError(
        error.ServerSignatureMismatch,
        client.handleServerFinal("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    );
    try testing.expect(!client.authenticated());
}

test "a server signature of the wrong length is rejected" {
    const gpa = testing.allocator;
    var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    });
    defer client.deinit();
    try client.handleServerFirst("r=nonce-server,s=YWJj,i=4096");
    _ = try client.clientFinal();
    try testing.expectError(error.InvalidKeyLength, client.handleServerFinal("v=YWJj"));
}

test "a server error is reported" {
    const gpa = testing.allocator;
    var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    });
    defer client.deinit();
    try client.handleServerFirst("r=nonce-server,s=YWJj,i=4096");
    _ = try client.clientFinal();

    try testing.expectEqual(@as(?messages.ServerFinal.Failure, null), client.serverError());
    try testing.expectError(
        error.AuthenticationFailed,
        client.handleServerFinal("e=unknown-user"),
    );
    try testing.expect(!client.authenticated());

    const failure = client.serverError().?;
    try testing.expectEqual(messages.ServerErrorValue.unknown_user, failure.value);
    try testing.expectEqualStrings("unknown-user", failure.text);
}

test "a generated nonce is fresh, printable, and long enough" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: [2][]const u8 = undefined;
    for (&seen) |*slot| {
        var client: Sha256Scram.Client = try .init(gpa, io, .{
            .username = "user",
            .password = "pencil",
        });
        defer client.deinit();

        // `attribute` cannot be used on a client-first message: it opens
        // with the GS2 header, whose flag is a bare `n` rather than an
        // `attr=value` pair. `r=` is the last attribute, so the nonce is
        // whatever follows it.
        const first = client.clientFirst();
        const nonce = first[std.mem.findLast(u8, first, ",r=").? + 3 ..];
        try testing.expect(messages.validNonce(nonce));
        // 24 random bytes, base64.
        try testing.expectEqual(@as(usize, 32), nonce.len);
        slot.* = try gpa.dupe(u8, nonce);
    }
    defer for (seen) |n| gpa.free(n);
    try testing.expect(!std.mem.eql(u8, seen[0], seen[1]));
}

test "deriveKeys agrees with compute" {
    const salt = "0123456789abcdef";
    var keys = try Sha256Scram.deriveKeys("pencil", salt, 4096);
    defer keys.deinit();
    const secret = try Sha256Scram.compute(testing.allocator, "pencil", salt, 4096, .raw);
    try testing.expectEqualSlices(u8, &keys.stored_key, &secret.stored_key);
    try testing.expectEqualSlices(u8, &keys.server_key, &secret.server_key);

    try testing.expectError(error.InvalidIterationCount, Sha256Scram.deriveKeys("p", salt, 0));
    try testing.expectError(error.SaltTooShort, Sha256Scram.deriveKeys("p", "", 4096));
}

test "a mechanism carries its own hash all the way through" {
    // The same exchange under two hashes differs in every derived field but
    // agrees on every plaintext one, which is the whole claim `Mechanism`
    // makes.
    const gpa = testing.allocator;
    const server_first = "r=nonce-server,s=YWJj,i=4096";

    var wide: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    });
    defer wide.deinit();
    var narrow: Sha1Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    });
    defer narrow.deinit();

    try testing.expectEqualStrings(wide.clientFirst(), narrow.clientFirst());
    try wide.handleServerFirst(server_first);
    try narrow.handleServerFirst(server_first);

    const wide_proof = try attribute(try wide.clientFinal(), 'p');
    const narrow_proof = try attribute(try narrow.clientFinal(), 'p');
    try testing.expectEqual(b64.Encoder.calcSize(32), wide_proof.len);
    try testing.expectEqual(b64.Encoder.calcSize(20), narrow_proof.len);
}

test "the server error text outlives the caller's buffer" {
    const gpa = testing.allocator;
    var client: Sha256Scram.Client = try .init(gpa, testing.io, .{
        .username = "user",
        .password = "pencil",
        .nonce = "nonce",
    });
    defer client.deinit();
    try client.handleServerFirst("r=nonce-server,s=YWJj,i=4096");
    _ = try client.clientFinal();

    // A message in memory the caller is about to reuse, which is what a
    // read buffer is.
    const message = try gpa.dupe(u8, "e=channel-bindings-dont-match");
    try testing.expectError(error.AuthenticationFailed, client.handleServerFinal(message));
    @memset(message, 'x');
    gpa.free(message);

    const failure = client.serverError().?;
    try testing.expectEqual(messages.ServerErrorValue.channel_bindings_dont_match, failure.value);
    try testing.expectEqualStrings("channel-bindings-dont-match", failure.text);
}
