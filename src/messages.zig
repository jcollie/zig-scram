// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! The SCRAM message grammar from [RFC 5802] section 7, and the GS2 header
//! from [RFC 5801] section 4 that a SCRAM exchange carries in front of it.
//!
//! Nothing here depends on which hash function the mechanism uses: the wire
//! format is the same for SCRAM-SHA-1 and SCRAM-SHA-256, and the only place
//! the hash shows through is the length of the base64 fields, which this
//! module passes along as text for `mechanism.zig` to decode. What it does do
//! is the grammar: splitting `attr=value` pairs, the `=2C` / `=3D` escaping a
//! username needs, the restricted alphabets of a nonce and a channel-binding
//! type, and the fixed order the RFC gives each message's attributes.
//!
//! ## Strictness
//!
//! The parsers follow the ABNF rather than accepting anything that could be
//! understood. Attributes have to arrive in the order the grammar lists them,
//! a value has to be non-empty, and an unknown attribute is tolerated only
//! where the grammar ends with `["," extensions]`. That is a deliberate
//! choice: this is an authentication protocol, every implementation generates
//! these messages from the same ABNF, and a parser that guesses is a parser
//! that can be steered.
//!
//! The one attribute that is *not* tolerated anywhere is `m`. RFC 5802
//! section 5.1 reserves it for a future extension that the receiver must
//! understand, so a message carrying one has to fail rather than be processed
//! without it.
//!
//! [RFC 5801]: https://www.rfc-editor.org/rfc/rfc5801
//! [RFC 5802]: https://www.rfc-editor.org/rfc/rfc5802

const std = @import("std");
const Io = std.Io;

const Allocator = std.mem.Allocator;
const b64 = std.base64.standard;

/// Longest salt a server is allowed to send. The RFC sets no limit; this is
/// the same bound `scram.Secret` stores, which is four times what PostgreSQL
/// and every other implementation in the wild generates.
pub const max_salt_length: usize = 64;

pub const ParseError = error{
    /// The message does not match the grammar: a missing or misplaced
    /// attribute, an empty value, a stray character.
    MalformedMessage,
    /// The message carried an `m=` attribute, which RFC 5802 section 5.1
    /// says the receiver must fail on rather than ignore.
    UnsupportedExtension,
    /// A base64 field would not decode.
    InvalidBase64,
    /// A nonce contained something outside the `printable` production.
    InvalidNonce,
    /// The iteration count is not a positive number that fits in a `u32`.
    InvalidIterationCount,
    /// The salt was empty, or longer than `max_salt_length`.
    SaltTooShort,
    SaltTooLong,
};

// ---------------------------------------------------------------------------
// Alphabets
// ---------------------------------------------------------------------------

/// `printable = %x21-2B / %x2D-7E` — visible ASCII except the comma, which is
/// the attribute separator. Note that `=` is *in* this set, so a base64 nonce
/// including its padding is a legal nonce.
pub fn isPrintable(c: u8) bool {
    return switch (c) {
        0x21...0x2b, 0x2d...0x7e => true,
        else => false,
    };
}

/// Whether `text` is a legal nonce: non-empty and entirely `printable`.
pub fn validNonce(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| if (!isPrintable(c)) return false;
    return true;
}

/// `cb-name = 1*(ALPHA / DIGIT / "." / "-")` — the channel-binding type names
/// registered with IANA, such as `tls-server-end-point` and `tls-exporter`.
pub fn validChannelBindingName(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-' => {},
        else => return false,
    };
    return true;
}

/// Whether `text` can be carried in an attribute value at all. `value-char`
/// excludes NUL and the comma; the comma is what `=2C` escaping is for, so a
/// name containing one is still usable, but a NUL is not representable.
pub fn validSaslName(text: []const u8) bool {
    return std.mem.findScalar(u8, text, 0) == null;
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

/// One `attr=value` pair. `value` borrows from the message it was parsed out
/// of.
pub const Attribute = struct {
    name: u8,
    value: []const u8,
};

/// Splits a message into its comma-separated `attr=value` pairs.
///
/// This is not a general CSV split: because `value-char` excludes the comma,
/// a comma always ends an attribute, and no quoting or escaping can hide one.
/// That is what makes the format safe to take apart before any of it has been
/// authenticated.
pub const Attributes = struct {
    rest: ?[]const u8,

    pub fn init(message: []const u8) Attributes {
        return .{ .rest = message };
    }

    pub fn next(self: *Attributes) ParseError!?Attribute {
        const rest = self.rest orelse return null;
        const field, const remainder = if (std.mem.findScalar(u8, rest, ',')) |comma|
            .{ rest[0..comma], rest[comma + 1 ..] }
        else
            .{ rest, null };
        self.rest = remainder;

        // `attr-val = ALPHA "=" value` with `value = 1*value-char`, so the
        // shortest legal attribute is three bytes.
        if (field.len < 3 or field[1] != '=') return error.MalformedMessage;
        if (!std.ascii.isAlphabetic(field[0])) return error.MalformedMessage;
        const value = field[2..];
        if (std.mem.findScalar(u8, value, 0) != null) return error.MalformedMessage;
        return .{ .name = field[0], .value = value };
    }

    /// The next attribute, which must be `name`. `m` is rejected wherever it
    /// appears, since a mandatory extension this version does not implement
    /// has to fail the exchange rather than be skipped.
    fn expect(self: *Attributes, name: u8) ParseError![]const u8 {
        const attr = try self.next() orelse return error.MalformedMessage;
        if (attr.name == 'm') return error.UnsupportedExtension;
        if (attr.name != name) return error.MalformedMessage;
        return attr.value;
    }

    /// Walks whatever is left, which the grammar allows to be extensions, and
    /// fails on `m`.
    fn finishExtensions(self: *Attributes) ParseError!void {
        while (try self.next()) |attr| {
            if (attr.name == 'm') return error.UnsupportedExtension;
        }
    }
};

// ---------------------------------------------------------------------------
// The GS2 header
// ---------------------------------------------------------------------------

/// What the client tells the server about channel binding, which is the
/// `gs2-cbind-flag` at the very front of the first message.
///
/// The choice is not a preference but an assertion about what the client saw,
/// and the server checks it: a client that says `none` when the server
/// offered a `-PLUS` mechanism, or `unsupported_by_server` when the server
/// did offer one, is a client whose mechanism list was tampered with, and the
/// server is required to abort. That check is the entire point of the flag,
/// so pick the variant that describes what was actually advertised.
pub const ChannelBinding = union(enum) {
    /// `n` — this client does not support channel binding.
    none,

    /// `y` — this client supports channel binding, but the server's mechanism
    /// list did not include the `-PLUS` variant. If that list was modified in
    /// flight the server will notice, because it knows what it advertised.
    unsupported_by_server,

    /// `p=<type>` — bind this exchange to the transport underneath it.
    bound: Data,

    /// The binding itself, which this library never computes: it is a
    /// property of the TLS connection, not of SCRAM. `type` is the IANA name
    /// and `data` the bytes that name refers to — for `tls-server-end-point`,
    /// the hash of the server certificate; for `tls-exporter`, the 32 bytes
    /// exported under the label `EXPORTER-Channel-Binding`.
    pub const Data = struct {
        type: []const u8,
        data: []const u8,
    };

    /// The mechanism name this flag has to be used with: `-PLUS` only when
    /// actually binding.
    pub fn wantsPlus(self: ChannelBinding) bool {
        return self == .bound;
    }
};

/// `gs2-header = gs2-cbind-flag "," [ authzid ] ","`.
///
/// The header is written once and then used twice: it prefixes the client's
/// first message, and it is also the first part of the `c=` channel-binding
/// input in the final message. A server compares the two, which is what stops
/// an attacker from rewriting the flag in the first message.
pub fn writeGs2Header(
    w: *Io.Writer,
    channel_binding: ChannelBinding,
    authzid: ?[]const u8,
) Io.Writer.Error!void {
    switch (channel_binding) {
        .none => try w.writeAll("n"),
        .unsupported_by_server => try w.writeAll("y"),
        .bound => |binding| {
            try w.writeAll("p=");
            try w.writeAll(binding.type);
        },
    }
    try w.writeByte(',');
    if (authzid) |id| {
        try w.writeAll("a=");
        try writeSaslName(w, id);
    }
    try w.writeByte(',');
}

// ---------------------------------------------------------------------------
// saslname
// ---------------------------------------------------------------------------

/// Writes a username or authorization identity with the two escapes RFC 5802
/// section 5.1 defines: `,` as `=2C` and `=` as `=3D`.
///
/// The comma has to be escaped because it separates attributes. The equals
/// sign has to be escaped because otherwise `=2C` in a real username would be
/// indistinguishable from an escaped comma.
pub fn writeSaslName(w: *Io.Writer, name: []const u8) Io.Writer.Error!void {
    var start: usize = 0;
    for (name, 0..) |c, i| {
        const escape = switch (c) {
            ',' => "=2C",
            '=' => "=3D",
            else => continue,
        };
        try w.writeAll(name[start..i]);
        try w.writeAll(escape);
        start = i + 1;
    }
    try w.writeAll(name[start..]);
}

/// How many bytes `writeSaslName` will write.
pub fn saslNameLength(name: []const u8) usize {
    var len = name.len;
    for (name) |c| {
        if (c == ',' or c == '=') len += 2;
    }
    return len;
}

/// Reverses `writeSaslName`. Caller owns the result.
///
/// A bare `=` that does not begin `=2C` or `=3D` is not a username with an
/// unescaped equals sign in it — the grammar has no such thing — so it is
/// rejected rather than passed through.
pub fn unescapeSaslName(gpa: Allocator, text: []const u8) (ParseError || Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, text.len);

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] != '=') {
            out.appendAssumeCapacity(text[i]);
            i += 1;
            continue;
        }
        if (i + 3 > text.len) return error.MalformedMessage;
        const escape = text[i .. i + 3];
        if (std.mem.eql(u8, escape, "=2C")) {
            out.appendAssumeCapacity(',');
        } else if (std.mem.eql(u8, escape, "=3D")) {
            out.appendAssumeCapacity('=');
        } else {
            return error.MalformedMessage;
        }
        i += 3;
    }
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// server-first-message
// ---------------------------------------------------------------------------

/// `server-first-message = [reserved-mext ","] nonce "," salt ","
/// iteration-count ["," extensions]`.
///
/// Nothing in this message is authenticated when it arrives — the proof that
/// the server knew the password comes two messages later — so everything read
/// out of it is a parameter for a computation, never a decision.
pub const ServerFirst = struct {
    /// The client nonce with the server's own appended. Borrows from the
    /// message.
    nonce: []const u8,
    salt_buf: [max_salt_length]u8,
    salt_len: u8,
    iterations: u32,

    pub fn salt(self: *const ServerFirst) []const u8 {
        return self.salt_buf[0..self.salt_len];
    }

    pub fn parse(text: []const u8) ParseError!ServerFirst {
        var attrs: Attributes = .init(text);

        var self: ServerFirst = undefined;

        self.nonce = try attrs.expect('r');
        if (!validNonce(self.nonce)) return error.InvalidNonce;

        const salt_b64 = try attrs.expect('s');
        const salt_len = b64.Decoder.calcSizeForSlice(salt_b64) catch
            return error.InvalidBase64;
        if (salt_len == 0) return error.SaltTooShort;
        if (salt_len > max_salt_length) return error.SaltTooLong;
        b64.Decoder.decode(self.salt_buf[0..salt_len], salt_b64) catch
            return error.InvalidBase64;
        @memset(self.salt_buf[salt_len..], 0);
        self.salt_len = @intCast(salt_len);

        const iterations = try attrs.expect('i');
        // A leading zero, a sign or a space would all be accepted by a looser
        // parser; `posit-number` is digits with no leading zero, and anything
        // else means the message was not generated by a conforming server.
        if (iterations.len > 1 and iterations[0] == '0') return error.InvalidIterationCount;
        self.iterations = std.fmt.parseUnsigned(u32, iterations, 10) catch
            return error.InvalidIterationCount;
        if (self.iterations == 0) return error.InvalidIterationCount;

        try attrs.finishExtensions();
        return self;
    }
};

// ---------------------------------------------------------------------------
// server-final-message
// ---------------------------------------------------------------------------

/// The error values RFC 5802 section 7 registers for `e=`.
///
/// A server is allowed to send any of these, and is also allowed to send none
/// of them and fail silently, so the absence of an error is not evidence of
/// anything. What they are good for is diagnostics: `unknown_user` and
/// `invalid_proof` tell an operator which half of a failed login to look at,
/// and the `channel_binding` family says the two ends disagree about the
/// transport rather than about the password.
pub const ServerErrorValue = enum {
    invalid_encoding,
    extensions_not_supported,
    invalid_proof,
    channel_bindings_dont_match,
    server_does_support_channel_binding,
    channel_binding_not_supported,
    unsupported_channel_binding_type,
    unknown_user,
    invalid_username_encoding,
    no_resources,
    other_error,
    /// A `server-error-value-ext`: something not in the RFC's list. The text
    /// is kept in `ServerFinal.failure.text`.
    unrecognized,

    const names = [_][]const u8{
        "invalid-encoding",
        "extensions-not-supported",
        "invalid-proof",
        "channel-bindings-dont-match",
        "server-does-support-channel-binding",
        "channel-binding-not-supported",
        "unsupported-channel-binding-type",
        "unknown-user",
        "invalid-username-encoding",
        "no-resources",
        "other-error",
    };

    pub fn parse(text: []const u8) ServerErrorValue {
        for (names, 0..) |name, i| {
            if (std.mem.eql(u8, name, text)) return @enumFromInt(i);
        }
        return .unrecognized;
    }

    /// The wire spelling, or `"unrecognized"` for a value that had none.
    pub fn toString(self: ServerErrorValue) []const u8 {
        const i = @intFromEnum(self);
        return if (i < names.len) names[i] else "unrecognized";
    }
};

/// `server-final-message = (server-error / verifier) ["," extensions]`.
pub const ServerFinal = union(enum) {
    /// `v=` — base64 of the server's `ServerSignature`, still encoded because
    /// its length depends on the mechanism's hash. Borrows from the message.
    verifier: []const u8,

    /// `e=` — the exchange failed, and the server said why.
    failure: Failure,

    pub const Failure = struct {
        value: ServerErrorValue,
        /// The value as sent, kept so that an unregistered one is still
        /// reportable.
        text: []const u8,
    };

    pub fn parse(text: []const u8) ParseError!ServerFinal {
        var attrs: Attributes = .init(text);
        const first = try attrs.next() orelse return error.MalformedMessage;
        const self: ServerFinal = switch (first.name) {
            'v' => .{ .verifier = first.value },
            'e' => .{ .failure = .{
                .value = .parse(first.value),
                .text = first.value,
            } },
            'm' => return error.UnsupportedExtension,
            else => return error.MalformedMessage,
        };
        try attrs.finishExtensions();
        return self;
    }
};

// ---------------------------------------------------------------------------

const testing = std.testing;

test "attributes" {
    var attrs: Attributes = .init("r=abc,s=ZGVm,i=4096");

    const r = (try attrs.next()).?;
    try testing.expectEqual(@as(u8, 'r'), r.name);
    try testing.expectEqualStrings("abc", r.value);

    const s = (try attrs.next()).?;
    try testing.expectEqualStrings("ZGVm", s.value);

    const i = (try attrs.next()).?;
    try testing.expectEqualStrings("4096", i.value);

    try testing.expectEqual(@as(?Attribute, null), try attrs.next());
}

test "attributes rejects malformed pairs" {
    for ([_][]const u8{
        "", // no attribute at all
        "r", // no separator
        "r=", // empty value
        "rr=x", // attribute names are one letter
        "1=x", // and are letters
        "r=a\x00b", // NUL is not a value-char
    }) |text| {
        var attrs: Attributes = .init(text);
        try testing.expectError(error.MalformedMessage, attrs.next());
    }

    // An empty field between two commas is not an attribute either, and is
    // only reached after the first one parses.
    var trailing: Attributes = .init("r=a,,s=b");
    _ = try trailing.next();
    try testing.expectError(error.MalformedMessage, trailing.next());
}

test "saslname escaping" {
    var buf: [64]u8 = undefined;

    const cases = [_]struct { raw: []const u8, escaped: []const u8 }{
        .{ .raw = "user", .escaped = "user" },
        .{ .raw = "a,b", .escaped = "a=2Cb" },
        .{ .raw = "a=b", .escaped = "a=3Db" },
        .{ .raw = ",", .escaped = "=2C" },
        .{ .raw = "=2C", .escaped = "=3D2C" },
        .{ .raw = ",,==", .escaped = "=2C=2C=3D=3D" },
        .{ .raw = "", .escaped = "" },
    };

    for (cases) |case| {
        var w: Io.Writer = .fixed(&buf);
        try writeSaslName(&w, case.raw);
        try testing.expectEqualStrings(case.escaped, w.buffered());
        try testing.expectEqual(case.escaped.len, saslNameLength(case.raw));

        const back = try unescapeSaslName(testing.allocator, case.escaped);
        defer testing.allocator.free(back);
        try testing.expectEqualStrings(case.raw, back);
    }
}

test "unescapeSaslName rejects a bare escape" {
    for ([_][]const u8{ "=", "=2", "=4141", "a=b", "=2c" }) |text| {
        try testing.expectError(
            error.MalformedMessage,
            unescapeSaslName(testing.allocator, text),
        );
    }
}

test "gs2 header" {
    var buf: [64]u8 = undefined;

    var plain: Io.Writer = .fixed(&buf);
    try writeGs2Header(&plain, .none, null);
    try testing.expectEqualStrings("n,,", plain.buffered());

    var downgraded: Io.Writer = .fixed(&buf);
    try writeGs2Header(&downgraded, .unsupported_by_server, null);
    try testing.expectEqualStrings("y,,", downgraded.buffered());

    var bound: Io.Writer = .fixed(&buf);
    try writeGs2Header(&bound, .{ .bound = .{
        .type = "tls-server-end-point",
        .data = "irrelevant here",
    } }, null);
    try testing.expectEqualStrings("p=tls-server-end-point,,", bound.buffered());

    var authorized: Io.Writer = .fixed(&buf);
    try writeGs2Header(&authorized, .none, "other,user");
    try testing.expectEqualStrings("n,a=other=2Cuser,", authorized.buffered());
}

test "server-first-message" {
    const msg = try ServerFirst.parse(
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
    );
    try testing.expectEqualStrings("rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0", msg.nonce);
    try testing.expectEqual(@as(u32, 4096), msg.iterations);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81 },
        msg.salt(),
    );

    // Extensions after the iteration count are allowed and ignored.
    const extended = try ServerFirst.parse("r=abc,s=YWJj,i=1,x=ignored,y=also");
    try testing.expectEqual(@as(u32, 1), extended.iterations);
}

test "server-first-message rejects what the grammar does not allow" {
    const E = ParseError;
    const cases = [_]struct { text: []const u8, want: E }{
        // A mandatory extension has to fail, wherever it appears.
        .{ .text = "m=x,r=abc,s=YWJj,i=4096", .want = error.UnsupportedExtension },
        .{ .text = "r=abc,s=YWJj,i=4096,m=x", .want = error.UnsupportedExtension },
        // The order is fixed by the ABNF.
        .{ .text = "s=YWJj,r=abc,i=4096", .want = error.MalformedMessage },
        .{ .text = "r=abc,i=4096,s=YWJj", .want = error.MalformedMessage },
        // Missing attributes.
        .{ .text = "r=abc,s=YWJj", .want = error.MalformedMessage },
        .{ .text = "r=abc", .want = error.MalformedMessage },
        // A nonce is printable ASCII without commas.
        .{ .text = "r=a b,s=YWJj,i=4096", .want = error.InvalidNonce },
        .{ .text = "r=a\x7fb,s=YWJj,i=4096", .want = error.InvalidNonce },
        // Salt bounds and encoding.
        .{ .text = "r=abc,s=,i=4096", .want = error.MalformedMessage },
        .{ .text = "r=abc,s=!!!!,i=4096", .want = error.InvalidBase64 },
        // Iteration counts.
        .{ .text = "r=abc,s=YWJj,i=0", .want = error.InvalidIterationCount },
        .{ .text = "r=abc,s=YWJj,i=04096", .want = error.InvalidIterationCount },
        .{ .text = "r=abc,s=YWJj,i=-1", .want = error.InvalidIterationCount },
        .{ .text = "r=abc,s=YWJj,i=4294967296", .want = error.InvalidIterationCount },
        .{ .text = "r=abc,s=YWJj,i=x", .want = error.InvalidIterationCount },
    };
    for (cases) |case| {
        try testing.expectError(case.want, ServerFirst.parse(case.text));
    }

    // A salt longer than we will store.
    var long: [max_salt_length + 1]u8 = @splat('x');
    var encoded: [b64.Encoder.calcSize(max_salt_length + 1)]u8 = undefined;
    var buf: [encoded.len + 32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "r=abc,s={s},i=1", .{
        b64.Encoder.encode(&encoded, &long),
    });
    try testing.expectError(error.SaltTooLong, ServerFirst.parse(text));
}

test "server-final-message" {
    switch (try ServerFinal.parse("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")) {
        .verifier => |v| try testing.expectEqualStrings("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", v),
        .failure => return error.TestUnexpectedResult,
    }

    switch (try ServerFinal.parse("e=invalid-proof")) {
        .verifier => return error.TestUnexpectedResult,
        .failure => |f| {
            try testing.expectEqual(ServerErrorValue.invalid_proof, f.value);
            try testing.expectEqualStrings("invalid-proof", f.text);
        },
    }

    switch (try ServerFinal.parse("e=something-new")) {
        .verifier => return error.TestUnexpectedResult,
        .failure => |f| {
            try testing.expectEqual(ServerErrorValue.unrecognized, f.value);
            try testing.expectEqualStrings("something-new", f.text);
        },
    }

    try testing.expectError(error.MalformedMessage, ServerFinal.parse("x=y"));
    try testing.expectError(error.UnsupportedExtension, ServerFinal.parse("m=x"));
    try testing.expectError(error.UnsupportedExtension, ServerFinal.parse("v=YWJj,m=x"));
}

test "every registered server error round trips" {
    inline for (@typeInfo(ServerErrorValue).@"enum".fields) |field| {
        const value: ServerErrorValue = @enumFromInt(field.value);
        if (value == .unrecognized) continue;
        try testing.expectEqual(value, ServerErrorValue.parse(value.toString()));
    }
    try testing.expectEqualStrings("unrecognized", ServerErrorValue.unrecognized.toString());
}

test "alphabets" {
    try testing.expect(validNonce("abcDEF123+/="));
    try testing.expect(!validNonce(""));
    try testing.expect(!validNonce("a,b"));
    try testing.expect(!validNonce("a b"));
    try testing.expect(!validNonce("a\x7f"));

    try testing.expect(validChannelBindingName("tls-server-end-point"));
    try testing.expect(validChannelBindingName("tls-exporter"));
    try testing.expect(validChannelBindingName("tls-unique"));
    try testing.expect(!validChannelBindingName(""));
    try testing.expect(!validChannelBindingName("tls_unique"));
    try testing.expect(!validChannelBindingName("a,b"));

    try testing.expect(validSaslName("user"));
    try testing.expect(validSaslName("a,b=c"));
    try testing.expect(!validSaslName("a\x00b"));
}
