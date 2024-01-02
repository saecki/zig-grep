const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Stdout = std.fs.File.Writer;

pub const UserOptions = struct {
    before_context: u32 = 0,
    after_context: u32 = 0,
    color: bool = false,
    heading: bool = true,
    ignore_case: bool = false,
    follow_links: bool = false,
    hidden: bool = false,
    debug: bool = false,
    unicode: bool = true,
};

const UserArg = struct {
    kind: UserArgKind,
    short: ?u8,
    long: []const u8,
    help: []const u8,
};

const UserArgKind = union(enum) {
    value: UserArgValue,
    flag: UserArgFlag,
};

const UserArgValue = enum(u8) {
    Context,
    AfterContext,
    BeforeContext,
};
const UserArgFlag = enum(u8) {
    Hidden,
    FollowLinks,
    Color,
    NoHeading,
    IgnoreCase,
    Debug,
    NoUnicode,
    Help,
};

const USER_ARGS = [_]UserArg{
    .{
        .short = 'A',
        .long = "after-context",
        .kind = .{ .value = .AfterContext },
        .help = "prints the given number of following lines for each match",
    },
    .{
        .short = 'B',
        .long = "before-context",
        .kind = .{ .value = .BeforeContext },
        .help = "prints the given number of preceding lines for each match",
    },
    .{
        .short = 'c',
        .long = "color",
        .kind = .{ .flag = .Color },
        .help = "print with colors, highlighting the matched phrase in the output",
    },
    .{
        .kind = .{ .value = .Context },
        .short = 'C',
        .long = "context",
        .help = "prints the number of preceding and following lines for each match. this is equivalent to setting --before-context and --after-context",
    },
    .{
        .short = 'd',
        .long = "debug",
        .kind = .{ .flag = .Debug },
        .help = "print why paths aren't searched",
    },
    .{
        .short = 'f',
        .long = "follow-links",
        .kind = .{ .flag = .FollowLinks },
        .help = "follow symbolic links",
    },
    .{
        .short = 'h',
        .long = "hidden",
        .kind = .{ .flag = .Hidden },
        .help = "search hidden files and folders",
    },
    .{
        .short = null,
        .long = "help",
        .kind = .{ .flag = .Help },
        .help = "print this message",
    },
    .{
        .short = 'i',
        .long = "ignore-case",
        .kind = .{ .flag = .IgnoreCase },
        .help = "search case insensitive",
    },
    .{
        .short = null,
        .long = "no-heading",
        .kind = .{ .flag = .NoHeading },
        .help = "prints a single line including the filename for each match, instead of grouping matches by file",
    },
    .{
        .short = null,
        .long = "no-unicode",
        .kind = .{ .flag = .NoUnicode },
        .help = "disable unicode support",
    },
};

const HELP_MSG = genHelp(USER_ARGS.len, USER_ARGS) catch unreachable;
fn genHelp(comptime LEN: usize, args: [LEN]UserArg) ![]u8 {
    const MAX_HELP_MSG_WIDTH = 74;
    const SHORT_ARG_WIDTH = 4;
    const HELP_SPACE = 4;
    const ARG_PLACEHOLDER = " <arg>";

    var buf = [_]u8{0} ** (2 * USER_ARGS.len * MAX_HELP_MSG_WIDTH);
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    var msg = ArrayList(u8).init(fba.allocator());
    var writer = msg.writer();

    try writer.writeAll("usage: searcher [OPTIONS] PATTERN [PATH ...]\n");

    var max_long_arg_width = 0;
    for (args) |arg| {
        const width = switch (arg.kind) {
            .value => 2 + arg.long.len + ARG_PLACEHOLDER.len,
            .flag => 2 + arg.long.len,
        };
        max_long_arg_width = @max(max_long_arg_width, width);
    }
    const help_offset = SHORT_ARG_WIDTH + max_long_arg_width + HELP_SPACE;

    for (args) |arg| {
        // short
        if (arg.short) |short| {
            try writer.print(" -{c},", .{short});
        } else {
            try writer.writeAll("    ");
        }

        // long
        try writer.print("--{s}", .{arg.long});
        var used_width = SHORT_ARG_WIDTH + 2 + arg.long.len;
        switch (arg.kind) {
            .value => {
                try writer.writeAll(ARG_PLACEHOLDER);
                used_width += ARG_PLACEHOLDER.len;
            },
            .flag => {},
        }
        const padding = help_offset - used_width;
        try writer.writeByteNTimes(' ', padding);

        // help
        var current_width = help_offset;
        var word_iter = std.mem.splitScalar(u8, arg.help, ' ');

        if (word_iter.next()) |word| {
            try writer.writeAll(word);
            current_width += word.len;
        }

        while (word_iter.next()) |word| {
            const additional_width = 1 + word.len;
            if (current_width + additional_width > MAX_HELP_MSG_WIDTH) {
                try writer.writeByte('\n');
                try writer.writeByteNTimes(' ', help_offset);
                current_width = help_offset + word.len;
            } else {
                try writer.writeByte(' ');
                current_width += additional_width;
            }
            try writer.writeAll(word);
        }

        try writer.writeByte('\n');
    }
    return msg.items;
}

pub fn parseArgs(stdout: Stdout, opts: *UserOptions, input_paths: *ArrayList([]const u8)) !?[]const u8 {
    var args = std.process.args();

    // discard executable
    _ = args.next();

    var input_pattern: ?[]const u8 = null;
    parse: while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--")) {
            var long_arg: []const u8 = arg[2..];
            var value: ?[]const u8 = null;
            if (std.mem.indexOfScalar(u8, long_arg, '=')) |pos| {
                value = long_arg[pos + 1 ..];
                long_arg = long_arg[0..pos];
            }

            for (USER_ARGS) |user_arg| {
                if (std.mem.eql(u8, user_arg.long, long_arg)) {
                    if (try parseArg(stdout, opts, &args, user_arg, long_arg, value, true)) {
                        return null;
                    }

                    continue :parse;
                }
            }

            try stdout.print("Unknown option \"{s}\"\n", .{long_arg});
            return error.Input;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            const short_args = arg[1..];
            short_args: for (short_args, 0..) |short_arg, i| {
                const char_len = utf8_char_len(short_arg);
                if (char_len > 1) {
                    const char = short_args[i .. i + char_len];
                    try stdout.print("Unknown flag \"{s}\"\n", .{char});
                    return error.Input;
                }

                const last_short_arg = short_args.len == i + 1;
                var value: ?[]const u8 = null;
                if (!last_short_arg) {
                    if (short_args[i + 1] == '=') {
                        value = short_args[i + 2 ..];
                    }
                }

                for (USER_ARGS) |user_arg| {
                    if (user_arg.short == short_arg) {
                        const name: []const u8 = &.{short_arg};
                        if (try parseArg(stdout, opts, &args, user_arg, name, value, last_short_arg)) {
                            return null;
                        }

                        if (value) |_| {
                            continue :parse;
                        } else {
                            continue :short_args;
                        }
                    }
                }

                try stdout.print("Unknown option \"{c}\"\n", .{short_arg});
                return error.Input;
            }
        } else if (input_pattern == null) {
            input_pattern = arg;
        } else {
            try input_paths.append(arg);
        }
    }

    const pattern = input_pattern orelse {
        try stdout.print("Missing required positional argument [PATTERN]\n", .{});
        return error.Input;
    };

    return pattern;
}

fn parseArg(
    stdout: Stdout,
    opts: *UserOptions,
    args: *std.process.ArgIterator,
    user_arg: UserArg,
    name: []const u8,
    value: ?[]const u8,
    next_arg: bool,
) !bool {
    switch (user_arg.kind) {
        .value => |kind| {
            var num: u32 = 0;
            if (value) |v| {
                num = try parseNum(stdout, v, name);
            } else if (next_arg) {
                num = try expectNum(stdout, args, name);
            } else {
                try stdout.print("Missing value after \"{s}\"", .{name});
                return error.Input;
            }

            switch (kind) {
                .Context => {
                    opts.after_context = num;
                    opts.before_context = num;
                },
                .AfterContext => {
                    opts.after_context = num;
                },
                .BeforeContext => {
                    opts.before_context = num;
                },
            }
        },
        .flag => |kind| {
            if (value) |v| {
                try stdout.print("Didn't expect value for \"{s}\", found \"{s}\"\n", .{ name, v });
                return error.Input;
            }

            switch (kind) {
                .Hidden => opts.hidden = true,
                .FollowLinks => opts.follow_links = true,
                .Color => opts.color = true,
                .NoHeading => opts.heading = false,
                .IgnoreCase => opts.ignore_case = true,
                .Debug => opts.debug = true,
                .NoUnicode => opts.unicode = false,
                .Help => {
                    try printHelp(stdout);
                    return true;
                },
            }
        },
    }

    return false;
}

pub fn printHelp(stdout: Stdout) !void {
    try stdout.print(HELP_MSG, .{});
}

fn expectNumAfterShortArg(
    stdout: Stdout,
    args: *std.process.ArgIterator,
    short_args: []const u8,
    index: usize,
) !u32 {
    if (index != short_args.len - 1) {
        try stdout.print("Missing value after \"{s}\"", .{short_args[index .. index + 1]});
        return error.Input;
    }

    return expectNum(stdout, args, short_args[index .. index + 1]);
}

fn expectNum(
    stdout: Stdout,
    args: *std.process.ArgIterator,
    name: []const u8,
) !u32 {
    const str = args.next() orelse {
        try stdout.print("Missing value after \"{s}\"\n", .{name});
        return error.Input;
    };

    return parseNum(stdout, str, name);
}

fn parseNum(
    stdout: Stdout,
    str: []const u8,
    name: []const u8,
) !u32 {
    const num = std.fmt.parseInt(u32, str, 10) catch {
        try stdout.print("Expected number for \"{s}\", found \"{s}\"\n", .{ name, str });
        return error.Input;
    };

    return num;
}

fn utf8_char_len(first_byte: u8) usize {
    var leading_ones: u8 = 0;
    const HIGH_BYTE: u8 = 0x80;
    while (((HIGH_BYTE >> @truncate(leading_ones)) & first_byte) != 0) {
        leading_ones += 1;
    }
    switch (leading_ones) {
        0 => return 1,
        else => return @as(usize, leading_ones),
    }
}

fn check(string: []const u8, len: usize) !void {
    const first_byte = string[0];
    const char_len = utf8_char_len(first_byte);
    // std.debug.print("{s}, first_byte: {b}, char_len {}\n", .{ string, first_byte, char_len });
    try std.testing.expectEqual(char_len, len);
}

test "utf-8 char len" {
    try check("a", 1);
    try check("ö", 2);
    try check("\u{2757}", 3);
    try check("\u{01FAE0}", 4);
}
