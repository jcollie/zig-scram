// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! SCRAM-SHA-256 password verifiers in the format PostgreSQL stores in
//! `pg_authid.rolpassword`:
//!
//!     SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
//!
//! The string produced here is exactly what the server computes for
//! `CREATE ROLE ... PASSWORD 'plaintext'` under `password_encryption =
//! scram-sha-256`, so it can be handed to `PASSWORD '...'` verbatim and the
//! plaintext never has to reach the server.
//!
//! Derivation (RFC 5802 / RFC 7677):
//!
//!     SaltedPassword := PBKDF2-HMAC-SHA-256(SASLprep(password), salt, iterations, 32)
//!     ClientKey      := HMAC-SHA-256(SaltedPassword, "Client Key")
//!     StoredKey      := SHA-256(ClientKey)
//!     ServerKey      := HMAC-SHA-256(SaltedPassword, "Server Key")
//!
//! SASLprep is implemented in `saslprep.zig`, on top of the Unicode character
//! data from `uucode`.

const std = @import("std");
const Io = std.Io;

const saslprep = @import("saslprep.zig");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const b64 = std.base64.standard;

/// Length of StoredKey and ServerKey, in bytes.
pub const key_length = Sha256.digest_length;

/// PostgreSQL's built-in default (`SCRAM_DEFAULT_ITERATIONS`, also the default
/// of the `scram_iterations` GUC added in PostgreSQL 16).
pub const default_iterations: u32 = 4096;

/// PostgreSQL's `SCRAM_DEFAULT_SALT_LEN`.
pub const default_salt_length: usize = 16;

/// Longest salt this module will store. PostgreSQL generates 16-byte salts;
/// the extra room is only so that verifiers produced elsewhere still parse.
pub const max_salt_length: usize = 64;

/// The mechanism tag, including the separator that follows it.
pub const prefix = "SCRAM-SHA-256$";

/// Upper bound on the length of an encoded verifier, for sizing stack buffers.
pub const max_encoded_length = prefix.len +
    10 + // decimal digits of a u32
    1 + b64.Encoder.calcSize(max_salt_length) +
    1 + b64.Encoder.calcSize(key_length) +
    1 + b64.Encoder.calcSize(key_length);

/// How to prepare the plaintext before deriving keys from it.
pub const Normalization = enum {
    /// Apply SASLprep (RFC 4013), falling back to the raw bytes if it fails.
    /// This is what PostgreSQL does, so it is what reproduces the server's
    /// verifier for any password.
    saslprep,

    /// Use the password bytes as given. Correct only if the caller has already
    /// prepared the password, or knows it is pure ASCII.
    raw,
};

pub const Error = error{
    /// `iterations` was zero.
    InvalidIterationCount,
    /// The salt was empty.
    SaltTooShort,
    /// The salt was longer than `max_salt_length`.
    SaltTooLong,
    OutOfMemory,
};

pub const ParseError = error{
    /// The text does not start with `SCRAM-SHA-256$`.
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

/// Options for `generate`.
pub const Options = struct {
    /// PBKDF2 rounds. Must be at least 1; PostgreSQL uses `default_iterations`.
    iterations: u32 = default_iterations,
    /// Number of random salt bytes to draw. Must be in `1..=max_salt_length`.
    salt_length: usize = default_salt_length,
    normalization: Normalization = .saslprep,
};

/// A parsed or freshly derived verifier. Contains no secret material: the
/// plaintext cannot be recovered from it, though it is still enough to
/// impersonate the server to a client, so treat it as sensitive.
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
        // One scratch buffer per field: `encode` returns a slice into the
        // buffer it was handed, so sharing one across a single `print` would
        // let the last call clobber the earlier ones.
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

        const dollar = std.mem.indexOfScalar(u8, body, '$') orelse return error.MalformedVerifier;
        const params = body[0..dollar];
        const keys = body[dollar + 1 ..];

        const colon = std.mem.indexOfScalar(u8, params, ':') orelse return error.MalformedVerifier;
        const iterations = std.fmt.parseInt(u32, params[0..colon], 10) catch
            return error.InvalidIterationCount;
        if (iterations < 1) return error.InvalidIterationCount;

        const key_colon = std.mem.indexOfScalar(u8, keys, ':') orelse return error.MalformedVerifier;

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

    /// Recomputes the verifier from `password` using this secret's salt and
    /// iteration count and compares in constant time.
    pub fn verify(
        self: *const Secret,
        gpa: Allocator,
        password: []const u8,
        normalization: Normalization,
    ) Error!bool {
        const candidate = try compute(gpa, password, self.salt(), self.iterations, normalization);
        return std.crypto.timing_safe.eql([key_length]u8, candidate.stored_key, self.stored_key) and
            std.crypto.timing_safe.eql([key_length]u8, candidate.server_key, self.server_key);
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

/// Derives a verifier from `password` and a caller-supplied salt. Deterministic
/// — use this to reproduce an existing verifier or in tests; use `generate` for
/// new passwords.
///
/// `gpa` is only touched when SASLprep has real work to do, which means never
/// for an all-ASCII password or for `.raw`.
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

    const prepared: saslprep.Prepared = switch (normalization) {
        .saslprep => try saslprep.prepOrRaw(gpa, password),
        .raw => .{ .bytes = password, .owned = false },
    };
    defer prepared.deinit(gpa);

    // dk is exactly one PRF block, so pbkdf2 can only fail on rounds == 0.
    var salted_password: [key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &salted_password);
    std.crypto.pwhash.pbkdf2(&salted_password, prepared.bytes, salt, iterations, HmacSha256) catch
        unreachable;

    var client_key: [key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &client_key);
    HmacSha256.create(&client_key, "Client Key", &salted_password);

    var self: Secret = undefined;
    self.iterations = iterations;
    @memcpy(self.salt_buf[0..salt.len], salt);
    @memset(self.salt_buf[salt.len..], 0);
    self.salt_len = @intCast(salt.len);
    Sha256.hash(&client_key, &self.stored_key, .{});
    HmacSha256.create(&self.server_key, "Server Key", &salted_password);
    return self;
}

/// Derives a verifier from `password` with a fresh random salt drawn from `io`.
/// This is the entry point for enrolling a new password.
pub fn generate(gpa: Allocator, io: Io, password: []const u8, options: Options) Error!Secret {
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

// -------------------------------------------------------------------------

const testing = std.testing;

// RFC 7677 section 3 test vector: password "pencil", i=4096. The client proof
// and server signature published in the RFC are derived from this StoredKey
// and ServerKey, so matching it pins the whole chain.
test "RFC 7677 vector" {
    var salt: [16]u8 = undefined;
    try b64.Decoder.decode(&salt, "W22ZaJ0SNY7soEsUEjb6gQ==");

    const secret = try compute(testing.allocator, "pencil", &salt, 4096, .saslprep);
    var buf: [max_encoded_length]u8 = undefined;
    try testing.expectEqualStrings(
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==" ++
            "$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=" ++
            ":wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        try secret.bufPrint(&buf),
    );
}

const test_salt = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
const test_salt_b64 = "AAECAwQFBgcICQoLDA0ODw==";

fn expectVerifier(expected: []const u8, password: []const u8, iterations: u32) !void {
    const secret = try compute(testing.allocator, password, &test_salt, iterations, .saslprep);
    var buf: [max_encoded_length]u8 = undefined;
    try testing.expectEqualStrings(expected, try secret.bufPrint(&buf));
}

test "known vectors" {
    try expectVerifier("SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$THoPhoTAuqyoQsK4dUHncUzgfD8fdmhsgKZhWVqNP5U=" ++
        ":7YiHMMi2OcXGRogub03Ek06JRZ9bkhTOdCzHa5iPLiQ=", "secret", 4096);

    // Empty passwords are legal; PostgreSQL only warns about them.
    try expectVerifier("SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$nJ7NIpEhGWYJgkXlH8+EU0un6/m20+gSgCnEi8kapIM=" ++
        ":s24L6krFXWqocZ+wwtUc/8hxenyJ5AnMUHAahlBS4uY=", "", 4096);

    // Password longer than the HMAC block size, and the minimum round count.
    try expectVerifier("SCRAM-SHA-256$1:" ++ test_salt_b64 ++
        "$ZTYlV5N4QSw4xmvOfzGSnxTcpQTWxbcisTRImxbIA80=" ++
        ":IEnhPEuaGR7Cx3/2XdorpVQfrI9NDht2R4YM3/m9JlY=", "a" ** 200, 1);
}

test "non-default iteration count" {
    const secret = try compute(
        testing.allocator,
        "pencil",
        "[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81",
        10000,
        .saslprep,
    );
    var buf: [max_encoded_length]u8 = undefined;
    try testing.expectEqualStrings(
        "SCRAM-SHA-256$10000:W22ZaJ0SNY7soEsUEjb6gQ==" ++
            "$z4Hg41LinCuBiY125xvXsuoV6QcPtx7/KArQGOISR9I=" ++
            ":eUaz+XNmezOxVNp1JcGRtdgo/H4FFOk6GbHCbjqg3oQ=",
        try secret.bufPrint(&buf),
    );
}

test "non-ascii passwords go through saslprep" {
    // Both spellings of "pässwort" normalize to the same NFKC form, so they
    // hash to the same verifier.
    const passwort = "SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$5nRyNYWlAn925EkkUpfteTWgD/NNOwqZYJsLAYsRsMw=" ++
        ":g/w2oXxwi85Kk15YG4S4HVX/oIgItiNS7GCtTaXt7lA=";
    try expectVerifier(passwort, "p\u{00E4}sswort", 4096);
    try expectVerifier(passwort, "pa\u{0308}sswort", 4096);

    // U+2168 ROMAN NUMERAL NINE folds to "IX" — the RFC 4013 example.
    const roman = try compute(testing.allocator, "\u{2168}", &test_salt, 4096, .saslprep);
    const plain = try compute(testing.allocator, "IX", &test_salt, 4096, .saslprep);
    try testing.expect(roman.eql(&plain));
    try expectVerifier("SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$Hvybl93RfCHqfqLiTzsBHz9FA2JH0lY8NzX3ES+JAB0=" ++
        ":36RFvraaEsq6EdU8f0zs6/hpb0vgxhjNZecZXSUZKgs=", "\u{2168}", 4096);

    // A non-ASCII space is mapped to U+0020 before normalization.
    try expectVerifier("SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$2rk8ozQF6mFul4o/eBQJGFZYT30xZfbvIPbBLAWLciE=" ++
        ":pSG3jifpoVWrie8UI3R+dT6wAl5kSJ99Eq0WJFwgetU=", "a\u{00A0}b", 4096);
}

test "saslprep failures fall back to the raw bytes" {
    // Invalid UTF-8 cannot be prepared, so PostgreSQL hashes it as-is.
    try expectVerifier("SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$xR6HKQJtBQ2zCeXUSK4LrszRvnB02WYDXbe/cd4Sd6c=" ++
        ":pOJybOkVsjyZT6JvPvPFd1irux/lAQh3+Z57LkAjnxE=", "\xff\xfe", 4096);

    const raw = try compute(testing.allocator, "\xff\xfe", &test_salt, 4096, .raw);
    const fallback = try compute(testing.allocator, "\xff\xfe", &test_salt, 4096, .saslprep);
    try testing.expect(raw.eql(&fallback));
}

test ".raw skips preparation" {
    const raw = try compute(testing.allocator, "\u{2168}", &test_salt, 4096, .raw);
    const prepped = try compute(testing.allocator, "IX", &test_salt, 4096, .saslprep);
    try testing.expect(!raw.eql(&prepped));
}

test "round trip through parse" {
    const secret = try compute(testing.allocator, "hunter2", &test_salt, 4096, .saslprep);

    var buf: [max_encoded_length]u8 = undefined;
    const text = try secret.bufPrint(&buf);

    const parsed = try Secret.parse(text);
    try testing.expect(parsed.eql(&secret));
    try testing.expectEqual(@as(u32, 4096), parsed.iterations);
    try testing.expectEqualSlices(u8, &test_salt, parsed.salt());
}

test "verify" {
    const gpa = testing.allocator;
    const secret = try compute(gpa, "hunter2", &test_salt, 4096, .saslprep);
    try testing.expect(try secret.verify(gpa, "hunter2", .saslprep));
    try testing.expect(!try secret.verify(gpa, "hunter3", .saslprep));
    try testing.expect(!try secret.verify(gpa, "", .saslprep));

    // The secret was built from the prepared form of U+2168, which is "IX",
    // so both spellings verify under `.saslprep` but only "IX" does under `.raw`.
    const unicode = try compute(gpa, "\u{2168}", &test_salt, 4096, .saslprep);
    try testing.expect(try unicode.verify(gpa, "\u{2168}", .saslprep));
    try testing.expect(try unicode.verify(gpa, "IX", .saslprep));
    try testing.expect(try unicode.verify(gpa, "IX", .raw));
    try testing.expect(!try unicode.verify(gpa, "\u{2168}", .raw));
}

test "parse rejects malformed input" {
    const valid = "SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
        "$THoPhoTAuqyoQsK4dUHncUzgfD8fdmhsgKZhWVqNP5U=" ++
        ":7YiHMMi2OcXGRogub03Ek06JRZ9bkhTOdCzHa5iPLiQ=";
    _ = try Secret.parse(valid);

    try testing.expectError(error.UnsupportedMechanism, Secret.parse("md5abc"));
    try testing.expectError(error.UnsupportedMechanism, Secret.parse("SCRAM-SHA-1$" ++ valid));
    try testing.expectError(error.MalformedVerifier, Secret.parse("SCRAM-SHA-256$4096:AAAA"));
    try testing.expectError(error.MalformedVerifier, Secret.parse("SCRAM-SHA-256$4096$AAAA:AAAA"));
    try testing.expectError(error.InvalidIterationCount, Secret.parse(
        "SCRAM-SHA-256$x:" ++ test_salt_b64 ++
            "$THoPhoTAuqyoQsK4dUHncUzgfD8fdmhsgKZhWVqNP5U=:7YiHMMi2OcXGRogub03Ek06JRZ9bkhTOdCzHa5iPLiQ=",
    ));
    try testing.expectError(error.InvalidIterationCount, Secret.parse(
        "SCRAM-SHA-256$0:" ++ test_salt_b64 ++
            "$THoPhoTAuqyoQsK4dUHncUzgfD8fdmhsgKZhWVqNP5U=:7YiHMMi2OcXGRogub03Ek06JRZ9bkhTOdCzHa5iPLiQ=",
    ));
    try testing.expectError(error.InvalidKeyLength, Secret.parse(
        "SCRAM-SHA-256$4096:" ++ test_salt_b64 ++
            "$AAAA:7YiHMMi2OcXGRogub03Ek06JRZ9bkhTOdCzHa5iPLiQ=",
    ));
    try testing.expectError(error.SaltTooShort, Secret.parse(
        "SCRAM-SHA-256$4096:" ++
            "$THoPhoTAuqyoQsK4dUHncUzgfD8fdmhsgKZhWVqNP5U=:7YiHMMi2OcXGRogub03Ek06JRZ9bkhTOdCzHa5iPLiQ=",
    ));
}

test "argument validation" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidIterationCount, compute(gpa, "pw", &test_salt, 0, .raw));
    try testing.expectError(error.SaltTooShort, compute(gpa, "pw", "", 4096, .raw));
    try testing.expectError(
        error.SaltTooLong,
        compute(gpa, "pw", &[_]u8{0} ** (max_salt_length + 1), 4096, .raw),
    );
}

test "generate produces a fresh usable secret" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = try generate(gpa, io, "hunter2", .{});
    const b = try generate(gpa, io, "hunter2", .{});

    try testing.expectEqual(default_salt_length, a.salt().len);
    try testing.expectEqual(default_iterations, a.iterations);
    try testing.expect(!std.mem.eql(u8, a.salt(), b.salt()));
    try testing.expect(try a.verify(gpa, "hunter2", .saslprep));
    try testing.expect(!try a.verify(gpa, "hunter3", .saslprep));

    const c = try generate(gpa, io, "hunter2", .{ .iterations = 1, .salt_length = 32 });
    try testing.expectEqual(@as(usize, 32), c.salt().len);
    try testing.expect(try c.verify(gpa, "hunter2", .saslprep));

    try testing.expectError(error.SaltTooShort, generate(gpa, io, "pw", .{ .salt_length = 0 }));
    try testing.expectError(
        error.SaltTooLong,
        generate(gpa, io, "pw", .{ .salt_length = max_salt_length + 1 }),
    );
}
