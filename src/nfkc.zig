//! NFKC (Unicode Normalization Form KC), built on the character data that
//! [uucode] exposes. This is the normalization step of SASLprep; see
//! `saslprep.zig` for the rest of the profile.
//!
//! The algorithm is the one in [UAX #15]: compatibility decomposition,
//! canonical ordering, then canonical composition.
//!
//! [uucode]: https://github.com/jacobsandlund/uucode
//! [UAX #15]: https://www.unicode.org/reports/tr15/

const std = @import("std");
const uucode = @import("uucode");

const Allocator = std.mem.Allocator;

/// Hangul syllables decompose and compose arithmetically rather than through
/// the character database. Constants from [UAX #15] section 16.
const hangul = struct {
    const s_base: u21 = 0xAC00;
    const l_base: u21 = 0x1100;
    const v_base: u21 = 0x1161;
    const t_base: u21 = 0x11A7;
    const l_count: u21 = 19;
    const v_count: u21 = 21;
    const t_count: u21 = 28;
    const n_count: u21 = v_count * t_count;
    const s_count: u21 = l_count * n_count;
};

fn ccc(cp: u21) u8 {
    return uucode.get(.canonical_combining_class, cp);
}

/// Normalizes `input` to NFKC. Caller owns the returned slice.
pub fn normalize(gpa: Allocator, input: []const u21) Allocator.Error![]u21 {
    composites.ensureBuilt();

    var out: std.ArrayList(u21) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, input.len);

    for (input) |cp| try decomposeInto(gpa, &out, cp, 0);
    canonicalOrder(out.items);
    out.shrinkRetainingCapacity(composeInPlace(out.items));

    return out.toOwnedSlice(gpa);
}

/// Appends the full compatibility decomposition of `cp` to `out`.
///
/// The recursion terminates because Unicode guarantees decomposition mappings
/// are acyclic and shallow; `depth` is only a backstop against a corrupt table.
fn decomposeInto(gpa: Allocator, out: *std.ArrayList(u21), cp: u21, depth: u8) Allocator.Error!void {
    if (depth >= 16) {
        try out.append(gpa, cp);
        return;
    }

    if (cp >= hangul.s_base and cp < hangul.s_base + hangul.s_count) {
        const index = cp - hangul.s_base;
        try out.append(gpa, hangul.l_base + index / hangul.n_count);
        try out.append(gpa, hangul.v_base + (index % hangul.n_count) / hangul.t_count);
        const trailing = index % hangul.t_count;
        if (trailing != 0) try out.append(gpa, hangul.t_base + trailing);
        return;
    }

    // `.default` means the code point decomposes to itself. Every other type,
    // canonical or compatibility, is expanded: this is the K in NFKC.
    if (uucode.get(.decomposition_type, cp) == .default) {
        try out.append(gpa, cp);
        return;
    }

    var buffer: [1]u21 = undefined;
    const mapping = uucode.get(.decomposition_mapping, cp).with(&buffer, cp);
    for (mapping) |part| try decomposeInto(gpa, out, part, depth + 1);
}

/// Sorts each run of combining marks by canonical combining class, stably —
/// an insertion sort that never moves a character past a starter.
fn canonicalOrder(s: []u21) void {
    if (s.len < 2) return;
    var i: usize = 1;
    while (i < s.len) : (i += 1) {
        const cp = s[i];
        const cp_class = ccc(cp);
        if (cp_class == 0) continue;

        var j = i;
        while (j > 0 and ccc(s[j - 1]) > cp_class) : (j -= 1) s[j] = s[j - 1];
        s[j] = cp;
    }
}

/// Canonical composition, in place. Returns the new length.
///
/// This is the algorithm from UAX #15: walk the string keeping track of the
/// most recent starter, and fold each following character into it when a
/// primary composite exists and nothing blocks the pair.
fn composeInPlace(s: []u21) usize {
    if (s.len == 0) return 0;

    var starter_pos: usize = 0;
    var starter_cp: u21 = s[0];
    var out_len: usize = 1;

    // A leading combining mark can never take part in a composition, so give
    // it a class higher than any real one to block the first pairing.
    var last_class: u16 = ccc(starter_cp);
    if (last_class != 0) last_class = 256;

    for (s[1..]) |cp| {
        const cp_class: u16 = ccc(cp);

        // `last_class == 0` means the starter is still adjacent; otherwise the
        // pair is blocked unless the intervening marks all sort lower.
        if (last_class < cp_class or last_class == 0) {
            if (composePair(starter_cp, cp)) |composite| {
                s[starter_pos] = composite;
                starter_cp = composite;
                continue;
            }
        }

        if (cp_class == 0) {
            starter_pos = out_len;
            starter_cp = cp;
        }
        last_class = cp_class;
        s[out_len] = cp;
        out_len += 1;
    }

    return out_len;
}

/// The primary composite of `a` and `b`, if there is one.
fn composePair(a: u21, b: u21) ?u21 {
    // Hangul leading + vowel jamo.
    if (a >= hangul.l_base and a < hangul.l_base + hangul.l_count and
        b >= hangul.v_base and b < hangul.v_base + hangul.v_count)
    {
        const l = a - hangul.l_base;
        const v = b - hangul.v_base;
        return hangul.s_base + (l * hangul.v_count + v) * hangul.t_count;
    }

    // Hangul LV syllable + trailing jamo. `t_base` itself is the filler that
    // stands for "no trailing consonant", so the range starts one past it.
    if (a >= hangul.s_base and a < hangul.s_base + hangul.s_count and
        (a - hangul.s_base) % hangul.t_count == 0 and
        b > hangul.t_base and b < hangul.t_base + hangul.t_count)
    {
        return a + (b - hangul.t_base);
    }

    return composites.lookup(a, b);
}

/// Reverse index from a canonical decomposition pair back to the character
/// that decomposes into it.
///
/// The character database only maps forwards, so the index has to be built by
/// sweeping the code space. That costs a few milliseconds, so it is done once
/// per process, on the first non-ASCII password that reaches normalization.
const composites = struct {
    const Entry = struct { pair: u42, cp: u21 };

    /// Unicode 17 defines roughly 950 primary composites; the headroom is for
    /// future versions of the character database.
    const capacity = 2048;

    const State = enum(u8) { idle, building, done };

    var state: std.atomic.Value(State) = .init(.idle);
    var entries: [capacity]Entry = undefined;
    var len: usize = 0;

    fn key(a: u21, b: u21) u42 {
        return (@as(u42, a) << 21) | b;
    }

    fn lessThan(_: void, x: Entry, y: Entry) bool {
        return x.pair < y.pair;
    }

    /// Builds the index the first time it is needed, at most once per process.
    ///
    /// `std.Io.Mutex` would need an `Io` threaded through every caller, so this
    /// is a hand-rolled once: whichever thread claims `.building` does the
    /// work, and any thread that arrives meanwhile spins until it publishes.
    /// The sweep takes a few milliseconds and the race window only exists on
    /// the very first non-ASCII password, so the spin is never hot.
    fn ensureBuilt() void {
        if (state.load(.acquire) == .done) return;
        if (state.cmpxchgStrong(.idle, .building, .acquire, .acquire) != null) {
            while (state.load(.acquire) != .done) std.atomic.spinLoopHint();
            return;
        }

        var n: usize = 0;
        var cp: u21 = 0;
        while (cp < 0x110000) : (cp += 1) {
            // Only canonical decompositions compose back; compatibility ones
            // are one-way by definition.
            if (uucode.get(.decomposition_type, cp) != .canonical) continue;

            // Full_Composition_Exclusion, in its three parts: the script
            // specifics listed in CompositionExclusions.txt, singleton
            // decompositions, and decompositions that start with a non-starter.
            if (uucode.get(.is_composition_exclusion, cp)) continue;

            var buffer: [1]u21 = undefined;
            const mapping = uucode.get(.decomposition_mapping, cp).with(&buffer, cp);
            if (mapping.len != 2) continue;
            if (ccc(mapping[0]) != 0) continue;

            if (n == capacity) @panic("more primary composites than `capacity`; raise it");
            entries[n] = .{ .pair = key(mapping[0], mapping[1]), .cp = cp };
            n += 1;
        }

        std.mem.sort(Entry, entries[0..n], {}, lessThan);
        len = n;
        // Release pairs with the acquire loads above, so a reader that sees
        // `.done` also sees the finished table.
        state.store(.done, .release);
    }

    fn lookup(a: u21, b: u21) ?u21 {
        const wanted = key(a, b);
        var lo: usize = 0;
        var hi: usize = len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const entry = entries[mid];
            if (wanted < entry.pair) {
                hi = mid;
            } else if (wanted > entry.pair) {
                lo = mid + 1;
            } else {
                return entry.cp;
            }
        }
        return null;
    }
};

// -------------------------------------------------------------------------

const testing = std.testing;

/// Convenience wrapper so the tests can work in UTF-8.
fn normalizeUtf8(gpa: Allocator, input: []const u8) ![]u8 {
    var cps: std.ArrayList(u21) = .empty;
    defer cps.deinit(gpa);
    var view = try std.unicode.Utf8View.init(input);
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| try cps.append(gpa, cp);

    const normalized = try normalize(gpa, cps.items);
    defer gpa.free(normalized);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var buffer: [4]u8 = undefined;
    for (normalized) |cp| {
        const n = try std.unicode.utf8Encode(cp, &buffer);
        try out.appendSlice(gpa, buffer[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

fn expectNormalized(expected: []const u8, input: []const u8) !void {
    const actual = try normalizeUtf8(testing.allocator, input);
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings(expected, actual);
}

test "composition" {
    // Combining sequence composes to the precomposed character.
    try expectNormalized("\u{00C0}", "A\u{0300}");
    try expectNormalized("\u{1E69}", "s\u{0323}\u{0307}");
    // Marks are reordered by combining class before composing, so the two
    // spellings of s-with-dot-below-and-dot-above agree.
    try expectNormalized("\u{1E69}", "s\u{0307}\u{0323}");
    // Already composed input is unchanged.
    try expectNormalized("\u{00C0}", "\u{00C0}");
}

test "compatibility decomposition" {
    try expectNormalized("fi", "\u{FB01}"); // ﬁ ligature
    try expectNormalized("25", "\u{FF12}\u{FF15}"); // fullwidth digits
    // Vulgar fraction: the slash is U+2044 FRACTION SLASH, not ASCII '/'.
    try expectNormalized("1\u{2044}2", "\u{00BD}");
    try expectNormalized("(1)", "\u{2474}"); // parenthesized digit one
    try expectNormalized("i9", "\u{2170}\u{2079}"); // small roman one, superscript nine
    // U+FDFA expands to eighteen code points, the longest mapping there is.
    try expectNormalized("\u{0635}\u{0644}\u{0649} \u{0627}\u{0644}\u{0644}\u{0647} " ++
        "\u{0639}\u{0644}\u{064A}\u{0647} \u{0648}\u{0633}\u{0644}\u{0645}", "\u{FDFA}");
}

test "composition exclusions are not recomposed" {
    // U+0958 is in CompositionExclusions.txt, so NFKC leaves the decomposed
    // form rather than putting it back together.
    try expectNormalized("\u{0915}\u{093C}", "\u{0958}");
    // Singleton decomposition: U+212B ANGSTROM SIGN becomes U+00C5.
    try expectNormalized("\u{00C5}", "\u{212B}");
}

test "hangul" {
    // Conjoining jamo compose into a syllable, LV then LVT.
    try expectNormalized("\u{AC00}", "\u{1100}\u{1161}");
    try expectNormalized("\u{AC01}", "\u{1100}\u{1161}\u{11A8}");
    try expectNormalized("\u{AC01}", "\u{AC00}\u{11A8}");
    // Compatibility jamo decompose to conjoining jamo but have nothing to
    // compose with on their own.
    try expectNormalized("\u{1100}", "\u{3131}");
}

test "ascii and empty are unchanged" {
    try expectNormalized("", "");
    try expectNormalized("hunter2", "hunter2");
}

test "blocked composition" {
    // The cedilla (class 202) sits between A and the grave (class 230), and
    // 202 < 230 does not block, so this composes to A-grave plus cedilla...
    try expectNormalized("\u{00C0}\u{0327}", "A\u{0327}\u{0300}");
    // ...but a starter in between blocks it entirely.
    try expectNormalized("AB\u{0300}", "AB\u{0300}");
}

test "composite table is complete" {
    composites.ensureBuilt();
    try testing.expect(composites.len > 900);
    try testing.expect(composites.len < composites.capacity);
    try testing.expectEqual(@as(?u21, 0x00C0), composites.lookup(0x0041, 0x0300));
    try testing.expectEqual(@as(?u21, null), composites.lookup(0x0041, 0x0041));
    // Excluded, so absent from the table even though it decomposes canonically.
    try testing.expectEqual(@as(?u21, null), composites.lookup(0x0915, 0x093C));
}
