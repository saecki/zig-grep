const std = @import("std");
const ArrayList = std.ArrayList;
const Stdout = std.fs.File.Writer;

const main = @import("main.zig");
const UserOptions = main.UserOptions;

// Parses args into `opts` and `input_paths`. If the --help option was given a
// message is printed and null is returned. If the args were parsed successfully
// the *required* pattern is returned.
pub fn parseArgs(stdout: Stdout, opts: *UserOptions, input_paths: *ArrayList([]const u8)) !?[]const u8 {
    var args = std.process.args();

    // discard executable
    _ = args.next();

    var input_pattern: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--")) {
            const long_arg = arg[2..];
            if (std.mem.eql(u8, long_arg, "hidden")) {
                opts.hidden = true;
            } else if (std.mem.eql(u8, long_arg, "follow-links")) {
                opts.follow_links = true;
            } else if (std.mem.eql(u8, long_arg, "color")) {
                opts.color = true;
            } else if (std.mem.eql(u8, long_arg, "no-heading")) {
                opts.heading = false;
            } else if (std.mem.eql(u8, long_arg, "ignore-case")) {
                opts.ignore_case = true;
            } else if (std.mem.eql(u8, long_arg, "debug")) {
                opts.debug = true;
            } else if (std.mem.eql(u8, long_arg, "no-unicode")) {
                opts.unicode = false;
            } else if (std.mem.eql(u8, long_arg, "after-context")) {
                opts.after_context = try expectNum(stdout, &args, long_arg);
            } else if (std.mem.eql(u8, long_arg, "before-context")) {
                opts.before_context = try expectNum(stdout, &args, long_arg);
            } else if (std.mem.eql(u8, long_arg, "before-context")) {
                const n = try expectNum(stdout, &args, long_arg);
                opts.before_context = n;
                opts.after_context = n;
            } else if (std.mem.eql(u8, long_arg, "help")) {
                try printHelp(stdout);
                return null;
            } else {
                try stdout.print("Unknown option \"{s}\"\n", .{long_arg});
                return error.Input;
            }
        } else if (std.mem.startsWith(u8, arg, "-")) {
            const short_args = arg[1..];
            for (short_args, 0..) |a, i| {
                const char_len = utf8_char_len(a);
                if (char_len > 1) {
                    const char = short_args[i .. i + char_len];
                    try stdout.print("Unknown flag \"{s}\"\n", .{char});
                    return error.Input;
                }

                switch (a) {
                    'h' => opts.hidden = true,
                    'f' => opts.follow_links = true,
                    'c' => opts.color = true,
                    'i' => opts.ignore_case = true,
                    'd' => opts.debug = true,
                    'A' => {
                        const n = try expectNumAfterShortArg(stdout, &args, short_args, i);
                        opts.after_context = n;
                    },
                    'B' => {
                        const n = try expectNumAfterShortArg(stdout, &args, short_args, i);
                        opts.before_context = n;
                    },
                    'C' => {
                        const n = try expectNumAfterShortArg(stdout, &args, short_args, i);
                        opts.before_context = n;
                        opts.after_context = n;
                    },
                    else => {
                        try stdout.print("Unknown option \"{c}\"\n", .{a});
                        return error.Input;
                    },
                }
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

pub fn printHelp(stdout: Stdout) !void {
    const HELP_MESSAGE =
        \\
        \\usage: searcher [OPTIONS] PATTERN [PATH ...]
        \\ -A,--after-context <arg>     prints the given number of following lines
        \\                              for each match
        \\ -B,--before-context <arg>    prints the given number of preceding lines
        \\                              for each match
        \\ -c,--color                   print with colors, highlighting the matched
        \\                              phrase in the output
        \\ -C,--context <arg>           prints the number of preceding and following
        \\                              lines for each match. this is equivalent to
        \\                              setting --before-context and --after-context
        \\ -d,--debug                   print why paths aren't searched
        \\ -f,--follow-links            follow symbolic links
        \\ -h,--hidden                  search hidden files and folders
        \\    --help                    print this message
        \\ -i,--ignore-case             search case insensitive
        \\    --no-heading              prints a single line including the filename
        \\                              for each match, instead of grouping matches
        \\                              by file
        \\    --no-unicode              disable unicdoe support
        \\
    ;
    try stdout.print(HELP_MESSAGE, .{});
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
