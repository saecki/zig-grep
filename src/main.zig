const c = @cImport({
    @cInclude("rure.h");
});

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Dir = std.fs.Dir;
const File = std.fs.File;
const IterableDir = std.fs.IterableDir;
const BufferedStdout = std.io.BufferedWriter(4096, File.Writer).Writer;

const Context = struct {
    stdout: BufferedStdout,
    allocator: Allocator,
    regex: *c.rure,
    dir_stack: ArrayList(StackEntry),
    name_buf: ArrayList(u8),
    text_buf: ArrayList(u8),
    line_buf: [][]const u8,
};

const UserOptions = struct {
    before_context: usize = 0,
    after_context: usize = 0,
    color: bool = false,
    heading: bool = true,
    ignore_case: bool = false,
    follow_links: bool = false,
    hidden: bool = false,
    debug: bool = false,
};

const StackEntry = struct {
    prev_dirname_len: usize,
    iter: IterableDir.Iterator,
};

const GrepError = error{
    Input,
    Loop,
};

const ResourceError = error{
    AccessDenied,
    BadPathName,
    BrokenPipe,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    DeviceBusy,
    DiskQuota,
    FileBusy,
    FileLocksNotSupported,
    FileNotFound,
    FileSystem,
    FileTooBig,
    InputOutput,
    InvalidArgument,
    InvalidHandle,
    InvalidUtf8,
    IsDir,
    LockViolation,
    NameTooLong,
    NetNameDeleted,
    NetworkNotFound,
    NoDevice,
    NoSpaceLeft,
    NotDir,
    NotLink,
    NotOpenForReading,
    NotOpenForWriting,
    NotSupported,
    OperationAborted,
    OutOfMemory,
    PathAlreadyExists,
    PipeBusy,
    ProcessFdQuotaExceeded,
    SharingViolation,
    SymLinkLoop,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
    UnsupportedPointType,
    UnsupportedReparsePointType,
    WouldBlock,
};

pub fn main() !void {
    var unbufferred_stdout = std.io.getStdOut().writer();
    var buffered = std.io.bufferedWriter(unbufferred_stdout);
    var stdout = buffered.writer();

    run(stdout) catch |err| {
        if (err == error.Input) {
            try printHelp(stdout);
        } else if (err == error.Loop) {
            // print nothing
        } else {
            try stdout.print("{}\n", .{err});
        }

        stdout.context.flush() catch {};
        std.process.exit(1);
    };

    stdout.context.flush() catch {};
}

pub fn run(stdout: BufferedStdout) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // read arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // discard executable
    _ = args.next();

    var input_pattern: ?[]const u8 = null;
    var input_paths = ArrayList([]const u8).init(allocator);
    defer input_paths.deinit();

    var opts = UserOptions{};

    // parse command line arguments
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
                return;
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

    // compile regex
    const regex_flags: u32 = if (opts.ignore_case) @bitCast(c.RURE_FLAG_CASEI) else 0;
    var regex_error = c.rure_error_new();
    defer c.rure_error_free(regex_error);
    const maybe_regex = c.rure_compile(@ptrCast(pattern), pattern.len, regex_flags, null, regex_error);
    const regex = maybe_regex orelse {
        const error_message = c.rure_error_message(regex_error);
        try stdout.print("Error compiling pattern \"{s}\"\n{s}\n", .{ pattern, error_message });
        return error.Input;
    };
    defer c.rure_free(regex);

    // the stack of searched directories
    var dir_stack = ArrayList(StackEntry).init(allocator);
    defer dir_stack.deinit();
    var name_buf = ArrayList(u8).init(allocator);
    defer name_buf.deinit();

    // reuse text buffers
    var text_buf = ArrayList(u8).init(allocator);
    defer text_buf.deinit();
    var line_buf: [][]u8 = try allocator.alloc([]u8, opts.before_context);
    defer allocator.free(line_buf);

    var ctx = Context{
        .stdout = stdout,
        .allocator = allocator,
        .regex = regex,
        .dir_stack = dir_stack,
        .name_buf = name_buf,
        .text_buf = text_buf,
        .line_buf = line_buf,
    };


    if (input_paths.items.len == 0) {
        // canonicalize path
        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const abs_path = try std.fs.realpath(".", &path_buf);

        try searchPath(&ctx, &opts, null, abs_path);
    } else {
        for (input_paths.items) |input_path| {
            // canonicalize path
            var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const abs_path = try std.fs.realpath(input_path, &path_buf);

            try searchPath(&ctx, &opts, input_path, abs_path);
        }
    }
}

fn searchPath(
    ctx: *Context,
    opts: *const UserOptions,
    input_path: ?[]const u8,
    abs_path: []const u8,
) (GrepError || ResourceError)!void {
    if (input_path) |p| {
        const open_flags = .{ .mode = .read_only };
        const file = try std.fs.openFileAbsolute(abs_path, open_flags);
        defer file.close();

        const stat = try file.stat();
        switch (stat.kind) {
            .file => {
                try searchFile(ctx, opts, p, file);
                return;
            },
            .directory => {},
            .sym_link => {
                if (opts.follow_links) {
                    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    const link = try std.fs.readLinkAbsolute(abs_path, &link_buf);
                    try searchLink(ctx, opts, abs_path, "", link);
                } else if (opts.debug) {
                    try ctx.stdout.print("Not following link: \"{s}\"\n", .{p});
                }
                return;
            },
            // ignore
            .block_device => return,
            .character_device => return,
            .named_pipe => return,
            .unix_domain_socket => return,
            .whiteout => return,
            .door => return,
            .event_port => return,
            .unknown => return,
        }
    }

    // open path to search
    const open_options = .{ .no_follow = true };
    const dir = try std.fs.openIterableDirAbsolute(abs_path, open_options);

    // the currently searched path name
    ctx.name_buf.clearRetainingCapacity();
    var dirname_len: usize = 0;
    if (input_path) |p| {
        try ctx.name_buf.appendSlice(p);
        dirname_len += p.len;
    }

    // push first dir entry
    try ctx.dir_stack.append(StackEntry{
        .prev_dirname_len = 0,
        .iter = dir.iterate(),
    });

    // recursively search the path
    while (ctx.dir_stack.items.len != 0) {
        ctx.name_buf.shrinkRetainingCapacity(dirname_len);

        var current = &ctx.dir_stack.items[ctx.dir_stack.items.len - 1];
        var entry = try current.iter.next() orelse {
            dirname_len = current.prev_dirname_len;
            current.iter.dir.close();
            _ = ctx.dir_stack.pop();
            continue;
        };

        var additional_len: usize = 0;
        if (dirname_len != 0 and ctx.name_buf.items[dirname_len - 1] != '/') {
            try ctx.name_buf.append(std.fs.path.sep);
            additional_len += 1;
        }
        try ctx.name_buf.appendSlice(entry.name);
        additional_len += entry.name.len;

        // skip hidden files
        if (!opts.hidden and entry.name[0] == '.') {
            if (opts.debug) {
                try ctx.stdout.print("Not searching hidden path: \"{s}\"\n", .{ctx.name_buf.items});
            }
            continue;
        }

        switch (entry.kind) {
            .file => {
                const open_flags = .{ .mode = .read_only };
                var file = try current.iter.dir.openFile(entry.name, open_flags);
                defer file.close();
                try searchFile(ctx, opts, ctx.name_buf.items, file);
            },
            .directory => {
                const new_dir = try current.iter.dir.openIterableDir(entry.name, open_options);
                const stack_entry = StackEntry{
                    .prev_dirname_len = dirname_len,
                    .iter = new_dir.iterate(),
                };
                try ctx.dir_stack.append(stack_entry);

                dirname_len += additional_len;
            },
            .sym_link => {
                if (opts.follow_links) {
                    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    const link = try current.iter.dir.readLink(entry.name, &link_buf);
                    var sub_path_idx: usize = 0;
                    if (input_path) |p| {
                        if (p.len == 0 or p[p.len - 1] == std.fs.path.sep) {
                            sub_path_idx = p.len;
                        } else {
                            sub_path_idx = p.len + 1;
                        }
                    }
                    const sub_path = ctx.name_buf.items[sub_path_idx..];
                    try searchLink(ctx, opts, abs_path, sub_path, link);
                } else if (opts.debug) {
                    try ctx.stdout.print("Not following link: \"{s}\"\n", .{ctx.name_buf.items});
                }
            },
            // ignore
            .block_device => {},
            .character_device => {},
            .named_pipe => {},
            .unix_domain_socket => {},
            .whiteout => {},
            .door => {},
            .event_port => {},
            .unknown => {},
        }
    }
}

fn searchLink(
    ctx: *Context,
    opts: *const UserOptions,
    abs_search_path: []const u8,
    sub_search_path: []const u8,
    link_path: []const u8,
) (GrepError || ResourceError)!void {
    // canonicalize path
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_link_path = try std.fs.realpath(link_path, &path_buf);

    if (symlinkLoops(abs_search_path, sub_search_path, abs_link_path)) {
        try ctx.stdout.print("Loop detected \"{s}\" points to ancetor \"{s}\"\n", .{ sub_search_path, link_path });
        return error.Loop;
    }

    // the stack of searched directories
    var dir_stack = ArrayList(StackEntry).init(ctx.allocator);
    defer dir_stack.deinit();
    var name_buf = ArrayList(u8).init(ctx.allocator);
    defer name_buf.deinit();

    var new_ctx = Context{
        .stdout = ctx.stdout,
        .allocator = ctx.allocator,
        .regex = ctx.regex,
        .dir_stack = dir_stack,
        .name_buf = name_buf,
        .text_buf = ctx.text_buf,
        .line_buf = ctx.line_buf,
    };

    try searchPath(&new_ctx, opts, link_path, abs_link_path);
}

fn searchFile(ctx: *Context, opts: *const UserOptions, path: []const u8, file: File) !void {
    // TODO: fixed size text buffer, read files incrementally
    const stat = try file.stat();
    try ctx.text_buf.resize(stat.size);

    const len = try file.readAll(ctx.text_buf.items);
    const text = ctx.text_buf.items[0..len];

    // detect binary files
    const contains_null_byte = std.mem.containsAtLeast(u8, text, 1, &[_]u8{0x00});
    if (contains_null_byte) {
        return;
    }

    // TODO: iterate over lines filling line buffer, while searching for pattern

    var file_has_match = false;
    var line_num: u32 = 1;
    var line_iter = std.mem.splitScalar(u8, text, '\n');
    var last_matched_line: ?[]const u8 = null;
    var current_pos: usize = 0;
    var match: c.rure_match = undefined;
    var match_iter = c.rure_iter_new(ctx.regex);
    defer c.rure_iter_free(match_iter);

    while (c.rure_iter_next(match_iter, @ptrCast(text), text.len, &match)) {
        // find current line
        var current_line: []const u8 = undefined;
        while (line_iter.peek()) |line| {
            const line_start = textIndex(text, line);
            const line_end = line_start + line.len;
            if (line_start <= match.start and line_end >= match.start) {
                current_line = line;
                break;
            }

            _ = line_iter.next();
            line_num += 1;
        }

        // print remainder of last matched line and set position to the current one
        var first_match_in_line = true;
        if (last_matched_line) |last| {
            first_match_in_line = last.ptr != current_line.ptr;

            if (first_match_in_line) {
                const last_line_end = textIndex(text, last) + last.len;
                if (current_pos < last_line_end) {
                    const remainder = text[current_pos..last_line_end];
                    try ctx.stdout.print("{s}\n", .{remainder});
                } else {
                    try ctx.stdout.print("\n", .{});
                }

                current_pos = textIndex(text, current_line);
            }
        } else {
            current_pos = textIndex(text, current_line);
        }

        // print heading
        if (!file_has_match and opts.heading) {
            if (opts.color) {
                try ctx.stdout.print("\x1b[35m", .{});
            }
            try ctx.stdout.print("{s}", .{path});
            if (opts.color) {
                try ctx.stdout.print("\x1b[0m", .{});
            }
            try ctx.stdout.print("\n", .{});

            file_has_match = true;
        }

        if (first_match_in_line) {
            // path
            if (!opts.heading) {
                if (opts.color) {
                    try ctx.stdout.print("\x1b[34m", .{});
                }
                try ctx.stdout.print("{s}", .{path});
                if (opts.color) {
                    try ctx.stdout.print("\x1b[0m", .{});
                }
                try ctx.stdout.print(":", .{});
            }

            // line number
            if (opts.color) {
                try ctx.stdout.print("\x1b[32m", .{});
            }
            try ctx.stdout.print("{}", .{line_num});
            if (opts.color) {
                try ctx.stdout.print("\x1b[0m", .{});
            }
            try ctx.stdout.print(":", .{});
        }

        // print preceding text
        if (current_pos != match.start) {
            const prev_text = text[current_pos..match.start];
            try ctx.stdout.print("{s}", .{prev_text});
        }

        // print the match
        const match_text = text[match.start..match.end];
        if (opts.color) {
            try ctx.stdout.print("\x1b[31m", .{});
        }
        try ctx.stdout.print("{s}", .{match_text});
        if (opts.color) {
            try ctx.stdout.print("\x1b[0m", .{});
        }

        last_matched_line = current_line;
        current_pos = match.end;
    }

    // print remainder of last matched line
    if (last_matched_line) |last| {
        const last_line_end = textIndex(text, last) + last.len;
        if (current_pos < last_line_end) {
            const remainder = text[current_pos..last_line_end];
            try ctx.stdout.print("{s}\n", .{remainder});
        } else {
            try ctx.stdout.print("\n", .{});
        }
    }

    if (file_has_match and opts.heading) {
        try ctx.stdout.print("\n", .{});
    }
}

fn textIndex(text: []const u8, slice_of_text: []const u8) usize {
    return @intFromPtr(slice_of_text.ptr) - @intFromPtr(text.ptr);
}

fn printHelp(stdout: BufferedStdout) !void {
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
        \\
    ;
    try stdout.print(HELP_MESSAGE, .{});
}

fn expectNumAfterShortArg(
    stdout: BufferedStdout,
    args: *std.process.ArgIterator,
    short_args: []const u8,
    index: usize,
) !usize {
    if (index != short_args.len - 1) {
        try stdout.print("Missing value after \"{s}\"", .{short_args[index .. index + 1]});
        return error.Input;
    }

    return expectNum(stdout, args, short_args[index .. index + 1]);
}

fn expectNum(
    stdout: BufferedStdout,
    args: *std.process.ArgIterator,
    name: []const u8,
) !usize {
    const str = args.next() orelse {
        try stdout.print("Missing value after \"{s}\"\n", .{name});
        return error.Input;
    };

    const num = std.fmt.parseInt(usize, str, 10) catch {
        try stdout.print("Expected number for \"{s}\", found \"{s}\"\n", .{ name, str });
        return error.Input;
    };

    return num;
}

fn symlinkLoops(
    abs_search_path: []const u8,
    sub_search_path: []const u8,
    abs_link_path: []const u8,
) bool {
    // loop outside search directory
    if (std.mem.startsWith(u8, abs_search_path, abs_link_path)) {
        return true;
    }

    // loop inside search directory
    if (std.mem.startsWith(u8, abs_link_path, abs_search_path)) {
        if (abs_search_path.len == abs_link_path.len) {
            return true;
        }

        const sub_link_path = abs_link_path[abs_search_path.len + 1 ..];
        if (std.mem.startsWith(u8, sub_search_path, sub_link_path)) {
            return true;
        }
    }

    return false;
}

test "symlink loop detection" {
    try std.testing.expect(symlinkLoops("/a/b/c", "d/e/f", "/a"));
    try std.testing.expect(symlinkLoops("/a/b/c", "d/e/f", "/a/b/c/d"));
    try std.testing.expect(!symlinkLoops("/a/b/c", "d/e/f", "/a/b/o"));
    try std.testing.expect(!symlinkLoops("/a/b/c", "d/e/f", "/a/b/c/d/o"));
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
    std.debug.print("{s}, first_byte: {b}, char_len {}\n", .{ string, first_byte, char_len });
    try std.testing.expectEqual(char_len, len);
}

test "utf-8 char len" {
    try check("a", 1);
    try check("ö", 2);
    try check("\u{2757}", 3);
    try check("\u{01FAE0}", 4);
}
