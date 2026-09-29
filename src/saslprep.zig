// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! SASLprep ([RFC 4013]), the stringprep profile SCRAM applies to a password
//! before deriving keys from it.
//!
//! There are two profiles, because the implementations that matter disagree
//! with the RFC. `prep` is PostgreSQL's, from its `src/common/saslprep.c`,
//! since reproducing what that server stores is what this module is mostly
//! for. It differs from RFC 4013 in three places:
//!
//!   * An all-ASCII password is returned untouched, skipping every step. That
//!     is sound for printable ASCII, since SASLprep is the identity on it. It
//!     is also why an ASCII control character never trips the
//!     prohibited-output check.
//!   * The prohibit and bidi checks run against the *mapped* string, before
//!     normalization, even though RFC 3454 describes them as checks on the
//!     output. So U+0340, which is prohibited and which NFKC turns into the
//!     permitted U+0300, is refused.
//!   * A password that maps to nothing at all is refused.
//!
//! `prepWith(..., .rfc4013)` is the RFC as written, for a stored string,
//! which is how RFC 5802 says SCRAM prepares a password: all four steps, in
//! order, with the prohibit and bidi checks on the normalized output. It
//! agrees with GNU libidn's SASLprep profile with `STRINGPREP_NO_UNASSIGNED`.
//!
//! Both profiles map U+200B, which RFC 3454 lists in both the table mapped to
//! a space (C.1.2) and the table mapped to nothing (B.1), to a space, as
//! PostgreSQL and libidn both do.
//!
//! [RFC 4013]: https://www.rfc-editor.org/rfc/rfc4013

const std = @import("std");
const nfkc = @import("nfkc.zig");
const tables = @import("stringprep_tables.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    /// The input is not well-formed UTF-8, so it cannot be prepared at all.
    InvalidUtf8,
    /// The input contains a character SASLprep forbids in its output, is
    /// unassigned as of Unicode 3.2, violates the bidirectional-text rules, or
    /// maps away to nothing.
    Prohibited,
    OutOfMemory,
};

/// A prepared password. `bytes` may alias the input, so keep the input alive
/// for as long as the result, and call `deinit` when done either way.
pub const Prepared = struct {
    bytes: []const u8,
    owned: bool,

    pub fn deinit(self: Prepared, gpa: Allocator) void {
        if (self.owned) gpa.free(self.bytes);
    }
};

/// Which implementation's reading of SASLprep to follow.
pub const Profile = enum {
    /// PostgreSQL's, which reproduces the verifier its server stores. See
    /// the top of this file for where it departs from the RFC.
    postgresql,
    /// RFC 4013 as written, preparing a stored string, as RFC 5802 asks of
    /// SCRAM: characters unassigned in Unicode 3.2 are refused, and the
    /// prohibit and bidi checks run on the normalized output.
    rfc4013,
};

/// Runs SASLprep over `input` the way PostgreSQL does.
pub fn prep(gpa: Allocator, input: []const u8) Error!Prepared {
    return prepWith(gpa, input, .postgresql);
}

/// Runs SASLprep over `input` under `profile`.
pub fn prepWith(gpa: Allocator, input: []const u8, profile: Profile) Error!Prepared {
    if (isAscii(input)) switch (profile) {
        .postgresql => return .{ .bytes = input, .owned = false },
        // Printable ASCII is its own SASLprep: nothing in it is mapped,
        // NFKC leaves it alone, it has no right-to-left characters, and none
        // of it is prohibited. The control characters are prohibited.
        .rfc4013 => {
            for (input) |byte| {
                if (byte < 0x20 or byte == 0x7f) return error.Prohibited;
            }
            return .{ .bytes = input, .owned = false };
        },
    };

    const decoded = try decode(gpa, input);
    defer gpa.free(decoded);

    // Step 1: map. C.1.2 becomes a space, B.1 is deleted, everything else is
    // kept. Done in place; `mapped` is the surviving prefix.
    var len: usize = 0;
    for (decoded) |cp| {
        if (tables.contains(tables.non_ascii_space, cp)) {
            decoded[len] = ' ';
            len += 1;
        } else if (tables.contains(tables.commonly_mapped_to_nothing, cp)) {
            // Dropped.
        } else {
            decoded[len] = cp;
            len += 1;
        }
    }
    const mapped = decoded[0..len];

    switch (profile) {
        .postgresql => {
            if (mapped.len == 0) return error.Prohibited;

            // Step 2: normalize to NFKC.
            const normalized = try nfkc.normalize(gpa, mapped);
            defer gpa.free(normalized);

            // Steps 3 and 4, on the mapped string as PostgreSQL checks them.
            try checkUnassigned(mapped);
            try checkProhibited(mapped);
            try checkBidi(mapped);

            return .{ .bytes = try encode(gpa, normalized), .owned = true };
        },
        .rfc4013 => {
            // Unassigned code points first, on the mapped string. RFC 3454
            // normalizes with Unicode 3.2's tables, under which a character
            // that 3.2 did not have is left alone and then found unassigned.
            // uucode's NFKC is a later Unicode's, which may turn such a
            // character into assigned ones -- U+1F100 into "0." -- and
            // checking before normalization gives 3.2's answer.
            try checkUnassigned(mapped);

            // Step 2: normalize to NFKC.
            const normalized = try nfkc.normalize(gpa, mapped);
            defer gpa.free(normalized);

            // Steps 3 and 4, on the output, where RFC 3454 puts them.
            try checkProhibited(normalized);
            try checkBidi(normalized);

            return .{ .bytes = try encode(gpa, normalized), .owned = true };
        },
    }
}

/// Code points unassigned in Unicode 3.2 (RFC 3454 table A.1), which a
/// stored string may not contain.
fn checkUnassigned(cps: []const u21) Error!void {
    for (cps) |cp| {
        if (tables.contains(tables.unassigned, cp)) return error.Prohibited;
    }
}

/// Step 3: prohibited output (RFC 4013 section 2.3).
fn checkProhibited(cps: []const u21) Error!void {
    for (cps) |cp| {
        if (tables.contains(tables.prohibited_output, cp)) return error.Prohibited;
    }
}

/// Step 4: bidirectional text. A string containing any RandALCat character
/// may not contain an LCat character, and must both start and end with a
/// RandALCat character. (RFC 3454 section 6.)
fn checkBidi(cps: []const u21) Error!void {
    if (containsAny(tables.rand_al_cat, cps)) {
        if (containsAny(tables.l_cat, cps)) return error.Prohibited;
        if (!tables.contains(tables.rand_al_cat, cps[0])) return error.Prohibited;
        if (!tables.contains(tables.rand_al_cat, cps[cps.len - 1])) return error.Prohibited;
    }
}

/// Runs SASLprep, falling back to the unprepared bytes if it fails.
///
/// This is what both the PostgreSQL server (`pg_be_scram_build_secret`) and
/// libpq do, so it is the behaviour to use when the goal is to agree with the
/// verifier PostgreSQL would have stored. Use `prep` directly to find out that
/// a password needed the fallback.
pub fn prepOrRaw(gpa: Allocator, input: []const u8) Allocator.Error!Prepared {
    return prep(gpa, input) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidUtf8, error.Prohibited => .{ .bytes = input, .owned = false },
    };
}

fn isAscii(input: []const u8) bool {
    for (input) |byte| {
        if (byte >= 0x80) return false;
    }
    return true;
}

fn containsAny(ranges: []const tables.Range, cps: []const u21) bool {
    for (cps) |cp| {
        if (tables.contains(ranges, cp)) return true;
    }
    return false;
}

fn decode(gpa: Allocator, input: []const u8) error{ InvalidUtf8, OutOfMemory }![]u21 {
    const view = std.unicode.Utf8View.init(input) catch return error.InvalidUtf8;

    var out: std.ArrayList(u21) = .empty;
    errdefer out.deinit(gpa);

    var it = view.iterator();
    while (it.nextCodepoint()) |cp| try out.append(gpa, cp);
    return out.toOwnedSlice(gpa);
}

fn encode(gpa: Allocator, cps: []const u21) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, cps.len);

    var buffer: [4]u8 = undefined;
    for (cps) |cp| {
        // Every code point here came from valid UTF-8 or from a normalization
        // table, so it is always encodable.
        const n = std.unicode.utf8Encode(cp, &buffer) catch unreachable;
        try out.appendSlice(gpa, buffer[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

// -------------------------------------------------------------------------

const testing = std.testing;

fn expectPrep(expected: []const u8, input: []const u8) !void {
    const prepared = try prep(testing.allocator, input);
    defer prepared.deinit(testing.allocator);
    try testing.expectEqualStrings(expected, prepared.bytes);
}

test "ascii passes through untouched" {
    try expectPrep("", "");
    try expectPrep("hunter2", "hunter2");
    // Control characters are prohibited output, but the ASCII fast path runs
    // first, exactly as in PostgreSQL.
    try expectPrep("a\tb\n", "a\tb\n");
}

test "RFC 4013 examples" {
    // Section 3 of RFC 4013.
    try expectPrep("IX", "I\u{00AD}X"); // SOFT HYPHEN mapped to nothing
    try expectPrep("user", "user");
    try expectPrep("USER", "USER");
    try expectPrep("a", "\u{00AA}"); // FEMININE ORDINAL INDICATOR -> "a"
    try expectPrep("IX", "\u{2168}"); // ROMAN NUMERAL NINE -> "IX"
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{0007}\u{0080}"));
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{0627}1"));
}

test "mapping and normalization" {
    // C.1.2 non-ASCII spaces become U+0020.
    try expectPrep("a b", "a\u{00A0}b");
    try expectPrep("a b", "a\u{3000}b");
    // B.1 characters are removed.
    try expectPrep("ab", "a\u{200C}b");
    // U+200B is in both C.1.2 and B.1. PostgreSQL tests the space table first,
    // so it becomes a space rather than disappearing; match that.
    try expectPrep("a b", "a\u{200B}b");
    // NFKC folds the compatibility character and composes the mark.
    try expectPrep("\u{00E9}", "e\u{0301}");
    try expectPrep("fi", "\u{FB01}");
}

test "a password that maps away entirely is prohibited" {
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{00AD}"));
}

test "prohibited and unassigned" {
    // U+2028 LINE SEPARATOR, C.2.2.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "a\u{2028}b"));
    // U+E000, private use, C.3.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "a\u{E000}b"));
    // U+FFFE, non-character, C.4.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "a\u{FFFE}b"));
    // U+0221 was unassigned in Unicode 3.2, so A.1 rejects it even though it
    // has been assigned since.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "a\u{0221}b"));
}

test "bidirectional rules" {
    // All-RandALCat is fine.
    try expectPrep("\u{05D0}\u{05D1}", "\u{05D0}\u{05D1}");
    // Mixing in an LCat character is not.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{05D0}a\u{05D1}"));
    // Neither is a RandALCat string that does not start and end with one.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{05D0}\u{0300}"));
}

test "invalid utf-8" {
    try testing.expectError(error.InvalidUtf8, prep(testing.allocator, "\xff\xfe"));
    try testing.expectError(error.InvalidUtf8, prep(testing.allocator, "\xc3"));
    // Surrogate half, encoded as CESU-8.
    try testing.expectError(error.InvalidUtf8, prep(testing.allocator, "\xed\xa0\x80"));
}

test "prepOrRaw falls back the way PostgreSQL does" {
    for ([_][]const u8{ "\xff\xfe", "a\u{2028}b", "\u{00AD}", "\u{05D0}a" }) |input| {
        const prepared = try prepOrRaw(testing.allocator, input);
        defer prepared.deinit(testing.allocator);
        try testing.expectEqualStrings(input, prepared.bytes);
        try testing.expect(!prepared.owned);
    }

    // A password that preps cleanly still gets the prepared form.
    const prepared = try prepOrRaw(testing.allocator, "\u{2168}");
    defer prepared.deinit(testing.allocator);
    try testing.expectEqualStrings("IX", prepared.bytes);
}

fn expectRfc(expected: []const u8, input: []const u8) !void {
    const prepared = try prepWith(testing.allocator, input, .rfc4013);
    defer prepared.deinit(testing.allocator);
    try testing.expectEqualStrings(expected, prepared.bytes);
}

test "the RFC 4013 profile agrees with libidn" {
    // Every answer here is GNU libidn's: stringprep() with the SASLprep
    // profile and STRINGPREP_NO_UNASSIGNED, which is a stored string.
    try expectRfc("hunter2", "hunter2");
    try expectRfc("IX", "I\u{00AD}X");
    try expectRfc("IX", "\u{2168}");
    try expectRfc("a", "\u{00AA}");
    try expectRfc("fi", "\u{FB01}");
    try expectRfc("\u{00E9}", "e\u{0301}");
    try expectRfc("a b", "a\u{200B}b");
    // Prohibited, but normalized to U+0300 before the check.
    try expectRfc("\u{0300}", "\u{0340}");
    try expectRfc("\u{00E8}", "e\u{0340}");
    try expectRfc("\u{05D0}\u{0300}\u{05D1}", "\u{05D0}\u{0340}\u{05D1}");
    // Mapping to nothing is allowed.
    try expectRfc("", "\u{00AD}");
    try expectRfc("\u{05D0}\u{05D1}", "\u{05D0}\u{05D1}");

    for ([_][]const u8{
        "a\tb", // ASCII control, C.2.1
        "\x7f",
        "a\u{2028}b", // LINE SEPARATOR, C.2.2
        "a\u{0221}b", // unassigned in Unicode 3.2
        "\u{1F100}", // unassigned in 3.2, though NFKC now makes it "0."
        "\u{05D0}a\u{05D1}", // bidi: RandALCat with LCat
    }) |input| {
        try testing.expectError(error.Prohibited, prepWith(testing.allocator, input, .rfc4013));
    }
}

test "the two profiles part where PostgreSQL departs from the RFC" {
    // An ASCII control character: PostgreSQL's shortcut lets it through.
    try expectPrep("a\tb", "a\tb");
    try testing.expectError(error.Prohibited, prepWith(testing.allocator, "a\tb", .rfc4013));
    // A prohibited character that normalization removes: PostgreSQL checks
    // before normalizing, the RFC after.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{0340}"));
    try expectRfc("\u{0300}", "\u{0340}");
    // A password that maps to nothing.
    try testing.expectError(error.Prohibited, prep(testing.allocator, "\u{00AD}"));
    try expectRfc("", "\u{00AD}");
}
