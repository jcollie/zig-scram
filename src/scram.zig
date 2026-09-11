// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! SCRAM-SHA-256: the instantiation of [RFC 5802] that [RFC 7677] defines,
//! and the one PostgreSQL speaks.
//!
//! Everything here is `mechanism.Mechanism(Sha256)` under a shorter name.
//! That module is where the code lives and where the protocol is explained;
//! this one exists because SHA-256 is what almost every caller wants, and
//! writing `scram.Client` should not require choosing a hash first.
//!
//! ## Verifiers
//!
//! `Secret` is a password verifier in the format PostgreSQL stores in
//! `pg_authid.rolpassword`:
//!
//!     SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
//!
//! The string produced here is exactly what the server computes for
//! `CREATE ROLE ... PASSWORD 'plaintext'` under `password_encryption =
//! scram-sha-256`, so it can be handed to `PASSWORD '...'` verbatim and the
//! plaintext never has to reach the server.
//!
//! The format is PostgreSQL's rather than anything the RFCs define — they
//! describe what a server must know, not how to write it down — so while
//! `ScramSha1.Secret` renders the same shape under a `SCRAM-SHA-1$` tag, only
//! the SHA-256 spelling is a string PostgreSQL will accept.
//!
//! ## The exchange
//!
//! `Client` runs the four-message authentication itself, against a PostgreSQL
//! server or anything else that speaks SCRAM:
//!
//!     var client: scram.Client = try .init(gpa, io, .{
//!         .username = "user",
//!         .password = "pencil",
//!     });
//!     defer client.deinit();
//!
//!     try conn.send(client.clientFirst());
//!     try client.handleServerFirst(try conn.receive());
//!     try conn.send(try client.clientFinal());
//!     try client.handleServerFinal(try conn.receive());
//!
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802
//! [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677

const std = @import("std");
const Io = std.Io;

const mechanism = @import("mechanism.zig");
const messages = @import("messages.zig");

const b64 = std.base64.standard;

/// SCRAM-SHA-256 (RFC 7677). Everything else in this file is an alias into it.
pub const ScramSha256 = mechanism.Mechanism(std.crypto.hash.sha2.Sha256);

/// SCRAM-SHA-1 (RFC 5802's own instantiation), for talking to something that
/// offers nothing better. SHA-1's collision resistance is gone, but SCRAM
/// leans on HMAC and PBKDF2, which do not need it; prefer SHA-256 anyway,
/// because a peer offering only SHA-1 is usually old in other ways too.
pub const ScramSha1 = mechanism.Mechanism(std.crypto.hash.Sha1);

pub const Secret = ScramSha256.Secret;
pub const Client = ScramSha256.Client;
pub const Keys = ScramSha256.Keys;
pub const Options = ScramSha256.GenerateOptions;
pub const Normalization = mechanism.Normalization;
pub const ChannelBinding = messages.ChannelBinding;
pub const Error = ScramSha256.Error;
pub const DeriveError = ScramSha256.DeriveError;
pub const ParseError = ScramSha256.ParseError;

pub const compute = ScramSha256.compute;
pub const generate = ScramSha256.generate;
pub const deriveKeys = ScramSha256.deriveKeys;

pub const key_length = ScramSha256.key_length;
pub const default_iterations = ScramSha256.default_iterations;
pub const default_salt_length = ScramSha256.default_salt_length;
pub const max_salt_length = ScramSha256.max_salt_length;
pub const max_encoded_length = ScramSha256.max_encoded_length;
pub const prefix = ScramSha256.prefix;
pub const name = ScramSha256.name;
pub const plus_name = ScramSha256.plus_name;

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
