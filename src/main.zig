//! CLI wrapper: reads a password and prints the PostgreSQL SCRAM-SHA-256
//! verifier for it.

const std = @import("std");
const Io = std.Io;

const scram = @import("scram_sha_256");

const usage =
    \\usage: scram_sha_256 [options]
    \\
    \\Reads a password from stdin and prints the PostgreSQL SCRAM-SHA-256
    \\verifier for it, suitable for:
    \\
    \\    ALTER ROLE alice PASSWORD 'SCRAM-SHA-256$4096:...';
    \\
    \\Options:
    \\  -p, --password TEXT   Use TEXT instead of reading stdin. Convenient, but
    \\                        the password is visible to other processes.
    \\  -i, --iterations N    PBKDF2 rounds (default 4096, PostgreSQL's own).
    \\  -s, --salt-length N   Random salt bytes (default 16, PostgreSQL's own).
    \\      --raw             Skip SASLprep and use the password bytes as given.
    \\                        Only correct if the password is already prepared.
    \\      --strict-prep     Fail instead of falling back to the raw bytes when
    \\                        SASLprep rejects the password. PostgreSQL itself
    \\                        always falls back, so this only reports the case.
    \\  -h, --help            Show this message.
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);

    var options: scram.Options = .{};
    var password: ?[]const u8 = null;
    var strict_prep = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (eqlAny(arg, &.{ "-h", "--help" })) {
            try writeOut(io, usage);
            return;
        } else if (eqlAny(arg, &.{"--raw"})) {
            options.normalization = .raw;
        } else if (eqlAny(arg, &.{"--strict-prep"})) {
            strict_prep = true;
        } else if (eqlAny(arg, &.{ "-p", "--password" })) {
            password = nextValue(io, args, &i);
        } else if (eqlAny(arg, &.{ "-i", "--iterations" })) {
            options.iterations = parseUint(io, u32, nextValue(io, args, &i));
        } else if (eqlAny(arg, &.{ "-s", "--salt-length" })) {
            options.salt_length = parseUint(io, usize, nextValue(io, args, &i));
        } else {
            fail(io, "unrecognized argument '{s}'", .{arg});
        }
    }

    const plaintext = password orelse try readStdinLine(io, arena);

    if (strict_prep and options.normalization == .saslprep) {
        const prepared = scram.saslprep.prep(gpa, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => fail(io, "password is not valid UTF-8", .{}),
            error.Prohibited => fail(io,
                \\password contains characters SASLprep prohibits, or breaks its
                \\bidirectional-text rules. PostgreSQL would hash the raw bytes
                \\instead; drop --strict-prep to do the same.
            , .{}),
        };
        prepared.deinit(gpa);
    }

    const secret = scram.generate(gpa, io, plaintext, options) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidIterationCount => fail(io, "--iterations must be at least 1", .{}),
        error.SaltTooShort => fail(io, "--salt-length must be at least 1", .{}),
        error.SaltTooLong => fail(io, "--salt-length must be at most {d}", .{scram.max_salt_length}),
    };

    var buf: [scram.max_encoded_length]u8 = undefined;
    try writeOut(io, try secret.bufPrint(&buf));
    try writeOut(io, "\n");
}

fn eqlAny(arg: []const u8, names: []const []const u8) bool {
    for (names) |name| if (std.mem.eql(u8, arg, name)) return true;
    return false;
}

fn nextValue(io: Io, args: []const [:0]const u8, i: *usize) []const u8 {
    i.* += 1;
    if (i.* >= args.len) fail(io, "'{s}' requires a value", .{args[i.* - 1]});
    return args[i.*];
}

fn parseUint(io: Io, comptime T: type, text: []const u8) T {
    return std.fmt.parseInt(T, text, 10) catch
        fail(io, "'{s}' is not a valid number", .{text});
}

/// Reads one line from stdin, without its terminator. A trailing newline is
/// optional so that both `echo pw | tool` and an interactive paste work.
fn readStdinLine(io: Io, arena: std.mem.Allocator) ![]const u8 {
    var buf: [4096]u8 = undefined;
    var file_reader: Io.File.Reader = .init(.stdin(), io, &buf);
    const reader = &file_reader.interface;

    const line = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => reader.buffered(),
        error.StreamTooLong => fail(io, "password is too long (limit {d} bytes)", .{buf.len}),
        error.ReadFailed => fail(io, "could not read the password from stdin", .{}),
    };
    return arena.dupe(u8, std.mem.trimEnd(u8, line, "\r"));
}

fn writeOut(io: Io, bytes: []const u8) !void {
    var buf: [scram.max_encoded_length + usage.len]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), io, &buf);
    try file_writer.interface.writeAll(bytes);
    try file_writer.interface.flush();
}

/// Reports a usage error on stderr and exits non-zero, so the user sees the
/// message rather than a Zig error return trace.
fn fail(io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [512]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stderr(), io, &buf);
    const w = &file_writer.interface;
    w.print("error: " ++ fmt ++ "\n", args) catch {};
    w.flush() catch {};
    std.process.exit(1);
}
