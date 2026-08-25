//! SASLprep ([RFC 4013]), the stringprep profile SCRAM applies to a password
//! before deriving keys from it.
//!
//! This follows PostgreSQL's `src/common/saslprep.c` rather than the RFC where
//! the two differ, because the point of the module is to reproduce what the
//! server stores. Two deliberate quirks come from there:
//!
//!   * An all-ASCII password is returned untouched, skipping every step. That
//!     is sound — SASLprep is the identity on ASCII — and it is also why an
//!     ASCII control character never trips the prohibited-output check.
//!   * The prohibit and bidi checks run against the *mapped* string, before
//!     normalization, even though RFC 3454 describes them as checks on the
//!     output. PostgreSQL has always done it this way.
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

/// Runs SASLprep over `input`.
pub fn prep(gpa: Allocator, input: []const u8) Error!Prepared {
    if (isAscii(input)) return .{ .bytes = input, .owned = false };

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
    if (mapped.len == 0) return error.Prohibited;

    // Step 2: normalize to NFKC.
    const normalized = try nfkc.normalize(gpa, mapped);
    defer gpa.free(normalized);

    // Step 3: prohibited output, and code points unassigned in Unicode 3.2.
    for (mapped) |cp| {
        if (tables.contains(tables.prohibited_output, cp)) return error.Prohibited;
        if (tables.contains(tables.unassigned, cp)) return error.Prohibited;
    }

    // Step 4: bidirectional text. A string containing any RandALCat character
    // may not contain an LCat character, and must both start and end with a
    // RandALCat character. (RFC 3454 section 6.)
    if (containsAny(tables.rand_al_cat, mapped)) {
        if (containsAny(tables.l_cat, mapped)) return error.Prohibited;
        if (!tables.contains(tables.rand_al_cat, mapped[0])) return error.Prohibited;
        if (!tables.contains(tables.rand_al_cat, mapped[mapped.len - 1])) return error.Prohibited;
    }

    return .{ .bytes = try encode(gpa, normalized), .owned = true };
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
