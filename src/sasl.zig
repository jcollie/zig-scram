// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! SCRAM as a [zig-sasl](https://git.jcollie.dev/jeff/zig-sasl) mechanism, so
//! that a protocol library can run the exchange without knowing what SCRAM is.
//!
//! This is a separate module, `scram-sasl`, rather than part of `scram`: the
//! dependency points this way round on purpose. zig-sasl knows nothing about
//! SCRAM and stays dependency-free; everything SCRAM-specific — including the
//! knowledge of how its four messages map onto a carrier that only has three
//! places to put them — lives here, with SCRAM.
//!
//! ## The mapping, which is the whole of the adapter
//!
//! SCRAM is four messages:
//!
//!     client-first → server-first → client-final → server-final
//!
//! SMTP, POP3 and IMAP can carry the first three in their AUTH exchange and
//! have nowhere to put the fourth: none of them can return data alongside a
//! successful outcome, which RFC 4954 states outright and which IMAP's tagged
//! OK does not change (it carries a `CAPABILITY` response code, not SASL
//! data). So `server-final` arrives as one more challenge, and the client
//! answers it with an empty response before the protocol reports success.
//!
//! That is why `Client.satisfied` exists. `server-final` is where the server
//! proves it knows `ServerKey` — the half of SCRAM that authenticates the
//! *server* — so a client that treats the protocol's success as the end of
//! the exchange has verified nothing. Here, `satisfied` is false until
//! `handleServerFinal` has run, and a profile that checks it cannot make that
//! mistake.

const std = @import("std");
const Io = std.Io;

const sasl = @import("sasl");
const scram = @import("scram");

/// Wraps a `scram.Client` — or a `Mechanism(Hash).Client` for any hash — as a
/// SASL client mechanism.
///
/// The wrapped client is borrowed, not owned: it allocates, and whoever built
/// it keeps the job of deinitializing it. That is the division the SASL
/// interface asks for, and it is what lets a protocol library that never
/// allocates drive a mechanism that does.
pub fn Adapter(comptime ScramClient: type) type {
    return struct {
        const Self = @This();

        inner: *ScramClient,
        /// The name to advertise and match against, which is the caller's to
        /// choose because only it knows whether channel binding is in use:
        /// `SCRAM-SHA-256` or `SCRAM-SHA-256-PLUS` are different mechanisms
        /// as far as a server is concerned.
        mechanism_name: []const u8,
        state: State = .start,

        pub const State = enum {
            /// `client-first` has not been asked for yet.
            start,
            /// `client-first` sent; waiting for `server-first`.
            first_sent,
            /// `client-final` sent; waiting for `server-final`, which is the
            /// server's turn to prove itself.
            proof_sent,
            /// `server-final` verified. The server is who it claims to be.
            verified,
            /// Something failed; this mechanism will produce no more.
            failed,
        };

        pub fn init(inner: *ScramClient, mechanism_name: []const u8) Self {
            return .{ .inner = inner, .mechanism_name = mechanism_name };
        }

        pub fn client(self: *Self) sasl.Client {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: sasl.Client.VTable = .{
            .name = name,
            .initial = initial,
            .respond = respond,
            .satisfied = satisfied,
            .cleartext = cleartext,
        };

        fn name(context: *anyopaque) []const u8 {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.mechanism_name;
        }

        fn initial(context: *anyopaque, out: *Io.Writer) sasl.Client.Error!sasl.Client.Initial {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.state != .start) return error.BadChallenge;
            try out.writeAll(self.inner.clientFirst());
            self.state = .first_sent;
            return .written;
        }

        fn respond(
            context: *anyopaque,
            challenge: []const u8,
            out: *Io.Writer,
        ) sasl.Client.Error!void {
            const self: *Self = @ptrCast(@alignCast(context));
            switch (self.state) {
                .first_sent => {
                    self.inner.handleServerFirst(challenge) catch |err| {
                        self.state = .failed;
                        return translateFirst(err);
                    };
                    const final = self.inner.clientFinal() catch |err| {
                        self.state = .failed;
                        return err; // OutOfMemory
                    };
                    try out.writeAll(final);
                    self.state = .proof_sent;
                },
                .proof_sent => {
                    // The server's proof. Nothing goes back but an
                    // acknowledgement, because the carrier had nowhere to put
                    // this message except a challenge of its own.
                    self.inner.handleServerFinal(challenge) catch |err| {
                        self.state = .failed;
                        return translateFinal(err);
                    };
                    self.state = .verified;
                },
                .start, .verified, .failed => {
                    self.state = .failed;
                    return error.BadChallenge;
                },
            }
        }

        fn satisfied(context: *anyopaque) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            return self.state == .verified;
        }

        fn cleartext(_: *anyopaque) bool {
            // The password never crosses the wire; what does is a proof over
            // a nonce the client contributed to.
            return false;
        }

        /// A malformed or unacceptable `server-first` is the peer sending
        /// nonsense, which is what `BadChallenge` is for.
        fn translateFirst(err: ScramClient.ServerFirstError) sasl.Client.Error {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.BadChallenge,
            };
        }

        /// A bad `server-final` divides in three, and the divisions are the
        /// point.
        ///
        /// A signature that does not verify — or one of the wrong length —
        /// means the peer does not hold this user's `ServerKey` and is
        /// therefore not the server, whatever else it has said. That is
        /// `BadServerProof`, and it is an accusation.
        ///
        /// `e=` is the server saying the exchange failed, which is a
        /// perfectly well-formed message from a peer doing nothing wrong.
        /// The protocol is about to report a rejection of its own; this is
        /// the same event, described by the party that knows why.
        ///
        /// Everything left is a message that does not parse.
        fn translateFinal(err: ScramClient.ServerFinalError) sasl.Client.Error {
            return switch (err) {
                error.ServerSignatureMismatch,
                error.InvalidKeyLength,
                => error.BadServerProof,
                error.AuthenticationFailed => error.Rejected,
                else => error.BadChallenge,
            };
        }
    };
}

/// SCRAM-SHA-256 ([RFC 7677](https://www.rfc-editor.org/rfc/rfc7677)) as a
/// SASL mechanism.
pub const Sha256 = Adapter(scram.ScramSha256.Client);

/// SCRAM-SHA-1 ([RFC 5802](https://www.rfc-editor.org/rfc/rfc5802)) as a SASL
/// mechanism.
pub const Sha1 = Adapter(scram.ScramSha1.Client);

const testing = std.testing;

/// RFC 7677 section 3's published exchange, which the library already checks
/// directly. Running the same transcript through the SASL vtable is what
/// shows the interface can carry it: the four messages have to fit into an
/// initial response and two challenges, with the fourth answered by nothing.
const rfc7677 = struct {
    const username = "user";
    const password = "pencil";
    const nonce = "rOprNGfwEbeRWgbNEkqO";
    const client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," ++
        "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
};

fn testClient() !scram.ScramSha256.Client {
    return try .init(testing.allocator, testing.io, .{
        .username = rfc7677.username,
        .password = rfc7677.password,
        .nonce = rfc7677.nonce,
    });
}

test "RFC 7677's exchange, driven entirely through the SASL interface" {
    var inner = try testClient();
    defer inner.deinit();
    var adapter: Sha256 = .init(&inner, scram.ScramSha256.name);
    const mechanism = adapter.client();

    try testing.expectEqualStrings("SCRAM-SHA-256", mechanism.name());
    // The password never crosses the wire, so this one may be used on a
    // carrier that is not encrypted.
    try testing.expect(!mechanism.cleartext());

    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    try testing.expectEqual(sasl.Client.Initial.written, try mechanism.initial(&out));
    try testing.expectEqualStrings(rfc7677.client_first, out.buffered());
    try testing.expect(!mechanism.satisfied());

    out = .fixed(&buf);
    try mechanism.respond(rfc7677.server_first, &out);
    try testing.expectEqualStrings(rfc7677.client_final, out.buffered());
    // The proof is sent and the server has still proved nothing.
    try testing.expect(!mechanism.satisfied());

    out = .fixed(&buf);
    try mechanism.respond(rfc7677.server_final, &out);
    // Nothing goes back: this is the acknowledgement the carrier forced,
    // empty and distinct from a cancellation.
    try testing.expectEqual(@as(usize, 0), out.buffered().len);
    try testing.expect(mechanism.satisfied());
}

test "a server that reports success without proving itself is not satisfied" {
    var inner = try testClient();
    defer inner.deinit();
    var adapter: Sha256 = .init(&inner, scram.ScramSha256.name);
    const mechanism = adapter.client();

    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    _ = try mechanism.initial(&out);
    out = .fixed(&buf);
    try mechanism.respond(rfc7677.server_first, &out);

    // Here a server says 235, or +OK, or a tagged OK, and sends no
    // server-final. It has the client's proof and has offered none of its
    // own, which is exactly what someone in the middle without the verifier
    // would do. The protocol layer is about to report success; `satisfied`
    // is the only thing standing between that and believing it.
    try testing.expect(!mechanism.satisfied());
}

test "a forged server signature is a bad proof, not a bad message" {
    var inner = try testClient();
    defer inner.deinit();
    var adapter: Sha256 = .init(&inner, scram.ScramSha256.name);
    const mechanism = adapter.client();

    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    _ = try mechanism.initial(&out);
    out = .fixed(&buf);
    try mechanism.respond(rfc7677.server_first, &out);

    // Well-formed, right length, wrong value.
    out = .fixed(&buf);
    try testing.expectError(error.BadServerProof, mechanism.respond(
        "v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        &out,
    ));
    try testing.expect(!mechanism.satisfied());

    // And the distinction the translation draws: a message that is simply
    // broken is a bad challenge rather than an accusation about the peer.
    var other = try testClient();
    defer other.deinit();
    var other_adapter: Sha256 = .init(&other, scram.ScramSha256.name);
    const other_mechanism = other_adapter.client();
    out = .fixed(&buf);
    _ = try other_mechanism.initial(&out);
    out = .fixed(&buf);
    try other_mechanism.respond(rfc7677.server_first, &out);
    out = .fixed(&buf);
    try testing.expectError(error.BadChallenge, other_mechanism.respond("not a message", &out));
}

test "a server reporting e= is a rejection, not a misbehaving peer" {
    var inner = try testClient();
    defer inner.deinit();
    var adapter: Sha256 = .init(&inner, scram.ScramSha256.name);
    const mechanism = adapter.client();

    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    _ = try mechanism.initial(&out);
    out = .fixed(&buf);
    try mechanism.respond(rfc7677.server_first, &out);

    // The server says the proof was wrong. Its message is well formed and it
    // is doing nothing wrong; it is refusing us, and the protocol is about to
    // say so in its own words as well.
    out = .fixed(&buf);
    try testing.expectError(error.Rejected, mechanism.respond("e=invalid-proof", &out));
    try testing.expect(!mechanism.satisfied());
}

test "a challenge out of turn is refused rather than misread" {
    var inner = try testClient();
    defer inner.deinit();
    var adapter: Sha256 = .init(&inner, scram.ScramSha256.name);
    const mechanism = adapter.client();

    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    // A challenge before the initial response has been asked for.
    try testing.expectError(error.BadChallenge, mechanism.respond(rfc7677.server_first, &out));
}

test {
    _ = Sha256;
    _ = Sha1;
}
