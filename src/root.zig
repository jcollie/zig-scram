// SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
// SPDX-License-Identifier: MIT

//! SCRAM-SHA-256 ([RFC 7677]) — password verifiers and the authentication
//! exchange they exist for.
//!
//! Deriving a verifier, which is what PostgreSQL stores:
//!
//!     var threaded: std.Io.Threaded = .init(gpa, .{});
//!     defer threaded.deinit();
//!
//!     const secret = try scram.generate(gpa, threaded.io(), "hunter2", .{});
//!     std.debug.print("{f}\n", .{secret});
//!     // SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>
//!
//! Feed that string to `CREATE ROLE ... PASSWORD '<verifier>'` and the
//! plaintext never leaves the client.
//!
//! Authenticating with one, which is the other end of the same protocol:
//!
//!     var client: scram.Client = try .init(gpa, io, .{
//!         .username = "user",
//!         .password = "hunter2",
//!     });
//!     defer client.deinit();
//!
//!     try conn.send(client.clientFirst());
//!     try client.handleServerFirst(try conn.receive());
//!     try conn.send(try client.clientFinal());
//!     try client.handleServerFinal(try conn.receive());
//!     // Returning from that last call is what authenticates the *server*.
//!
//! [RFC 7677]: https://www.rfc-editor.org/rfc/rfc7677

const std = @import("std");

pub const scram = @import("scram.zig");
pub const mechanism = @import("mechanism.zig");
pub const messages = @import("messages.zig");
pub const saslprep = @import("saslprep.zig");
pub const nfkc = @import("nfkc.zig");
pub const stringprep_tables = @import("stringprep_tables.zig");

/// SCRAM over any hash the RFCs name. `scram` is `Mechanism(Sha256)`.
pub const Mechanism = mechanism.Mechanism;
pub const ScramSha256 = scram.ScramSha256;
pub const ScramSha1 = scram.ScramSha1;

pub const Secret = scram.Secret;
pub const Client = scram.Client;
pub const Keys = scram.Keys;
pub const Options = scram.Options;
pub const Normalization = scram.Normalization;
pub const ChannelBinding = scram.ChannelBinding;
pub const ServerErrorValue = messages.ServerErrorValue;
pub const Error = scram.Error;
pub const DeriveError = scram.DeriveError;
pub const ParseError = scram.ParseError;

pub const generate = scram.generate;
pub const compute = scram.compute;
pub const deriveKeys = scram.deriveKeys;

pub const key_length = scram.key_length;
pub const default_iterations = scram.default_iterations;
pub const default_salt_length = scram.default_salt_length;
pub const max_salt_length = scram.max_salt_length;
pub const max_encoded_length = scram.max_encoded_length;
pub const prefix = scram.prefix;
pub const name = scram.name;
pub const plus_name = scram.plus_name;

test {
    _ = scram;
    _ = mechanism;
    _ = messages;
    _ = saslprep;
    _ = nfkc;
    _ = stringprep_tables;
}
