//! PostgreSQL SCRAM-SHA-256 password verifiers.
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

const std = @import("std");

pub const scram = @import("scram.zig");
pub const saslprep = @import("saslprep.zig");
pub const nfkc = @import("nfkc.zig");
pub const stringprep_tables = @import("stringprep_tables.zig");

pub const Secret = scram.Secret;
pub const Options = scram.Options;
pub const Normalization = scram.Normalization;
pub const Error = scram.Error;
pub const ParseError = scram.ParseError;

pub const generate = scram.generate;
pub const compute = scram.compute;

pub const key_length = scram.key_length;
pub const default_iterations = scram.default_iterations;
pub const default_salt_length = scram.default_salt_length;
pub const max_salt_length = scram.max_salt_length;
pub const max_encoded_length = scram.max_encoded_length;
pub const prefix = scram.prefix;

test {
    _ = scram;
    _ = saslprep;
    _ = nfkc;
    _ = stringprep_tables;
}
