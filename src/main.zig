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

const TEXT_BUF_SIZE = 1 << 19;

const Context = struct {
    stdout: BufferedStdout,
    allocator: Allocator,
    regex: *c.rure,
    dir_stack: *ArrayList(StackEntry),
    name_buf: *ArrayList(u8),
    text_buf: []u8,
    line_buf: *ArrayList([]const u8),
};

const UserOptions = struct {
    before_context: u32 = 0,
    after_context: u32 = 0,
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

pub fn main() void {
    wrap_run() catch {
        std.process.exit(1);
    };
}

fn wrap_run() !void {
    var unbufferred_stdout = std.io.getStdOut();
    defer unbufferred_stdout.close();
    var buffered = std.io.bufferedWriter(unbufferred_stdout.writer());
    defer buffered.flush() catch {};
    var stdout = buffered.writer();

    run(stdout) catch |err| {
        if (err == error.Input) {
            try printHelp(stdout);
        } else if (err == error.Loop) {
            // print nothing
        } else {
            try stdout.print("{}\n", .{err});
        }

        return err;
    };
}

fn run(stdout: BufferedStdout) !void {
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
    var regex_flags: u32 = c.RURE_DEFAULT_FLAGS;
    if (opts.ignore_case) {
        regex_flags |= c.RURE_FLAG_CASEI;
    }
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

    // reuse text buffer
    var text_buf = try allocator.alloc(u8, TEXT_BUF_SIZE);
    defer allocator.free(text_buf);
    var line_buf = ArrayList([]const u8).init(allocator);
    defer line_buf.deinit();
    try line_buf.ensureTotalCapacity(opts.before_context);

    var ctx = Context{
        .stdout = stdout,
        .allocator = allocator,
        .regex = regex,
        .dir_stack = &dir_stack,
        .name_buf = &name_buf,
        .text_buf = text_buf,
        .line_buf = &line_buf,
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
        .dir_stack = &dir_stack,
        .name_buf = &name_buf,
        .text_buf = ctx.text_buf,
        .line_buf = ctx.line_buf,
    };

    try searchPath(&new_ctx, opts, link_path, abs_link_path);
}

const ChunkBuffer = struct {
    reader: File.Reader,
    items: []u8,
    pos: usize,
    end: usize,
    is_last_chunk: bool,
};

fn searchFile(ctx: *Context, opts: *const UserOptions, path: []const u8, file: File) !void {
    var chunk_buf = ChunkBuffer{
        .reader = file.reader(),
        .items = ctx.text_buf,
        .pos = 0,
        .end = 0,
        .is_last_chunk = false,
    };

    var text = try refillLineBuffer(&chunk_buf, 0);

    var file_has_match = false;
    var line_num: u32 = 1;
    var last_printed_line: u32 = 0;
    var after_context_lines: u32 = 0;

    // detect binary files
    const contains_null_byte = std.mem.containsAtLeast(u8, text, 1, &[_]u8{0x00});
    if (contains_null_byte) {
        return;
    }

    while (true) {
        var line: []const u8 = undefined;
        var end_pos: usize = undefined;
        if (std.mem.indexOfScalarPos(u8, text, chunk_buf.pos, '\n')) |line_term_pos| {
            line = text[chunk_buf.pos..line_term_pos];
            end_pos = line_term_pos + 1;
        } else if (chunk_buf.is_last_chunk) {
            if (chunk_buf.pos < text.len) {
                // last line is missing a line terminator
                line = text[chunk_buf.pos..];
                end_pos = text.len;
            } else {
                // we're at the end of the file
                break;
            }
        } else {
            var new_start_pos = chunk_buf.pos;
            if (opts.before_context > 0) {
                // include lines that may have to be printed as `before_context`
                var cline_end = chunk_buf.pos;
                for (0..opts.before_context) |_| {
                    var cline_start: u32 = 0;
                    if (cline_end > 1) {
                        if (indexOfScalarPosRev(u8, text, cline_end - 1, '\n')) |pos| {
                            cline_start = @intCast(pos);
                        }
                    }

                    new_start_pos = cline_start;

                    if (cline_start == 0) {
                        break;
                    }
                    cline_end = cline_start;
                }
            }

            text = try refillLineBuffer(&chunk_buf, new_start_pos);
            continue;
        }

        var line_pos: u32 = 0;
        var line_has_match = false;
        while (line_pos < line.len) {
            var match: c.rure_match = undefined;
            const found = c.rure_find(ctx.regex, @ptrCast(line), line.len, line_pos, &match);
            if (!found) break;

            // print heading
            if (!file_has_match and opts.heading) {
                if (opts.color) {
                    try ctx.stdout.writeAll("\x1b[35m");
                }
                try ctx.stdout.writeAll(path);
                if (opts.color) {
                    try ctx.stdout.writeAll("\x1b[0m");
                }
                try ctx.stdout.writeByte('\n');
            }

            if (!line_has_match) {
                const unprinted_lines = line_num - last_printed_line - 1;
                // non-contigous lines separator
                if (opts.before_context > 0 or opts.after_context > 0) {
                    if (file_has_match and unprinted_lines > opts.before_context) {
                        try ctx.stdout.writeAll("--\n");
                    }
                }

                // before context lines
                const before_context_lines = @min(opts.before_context, unprinted_lines);
                if (before_context_lines > 0) {
                    std.debug.assert(chunk_buf.pos > 1);

                    // collect lines
                    var cline_end = chunk_buf.pos;
                    for (0..before_context_lines) |_| {
                        var cline_start: u32 = 0;
                        if (cline_end > 1) {
                            if (indexOfScalarPosRev(u8, text, cline_end - 1, '\n')) |pos| {
                                cline_start = @intCast(pos);
                            }
                        }

                        try ctx.line_buf.append(text[cline_start..cline_end]);

                        if (cline_start == 0) {
                            break;
                        }
                        cline_end = cline_start;
                    }

                    // print lines
                    var i = ctx.line_buf.items.len;
                    while (i > 0) {
                        i -= 1;
                        const cline_num = line_num - i - 1;
                        const cline = ctx.line_buf.items[i];

                        // line prefix
                        if (!opts.heading) {
                            try printPath(ctx, opts, path);
                            try ctx.stdout.writeByte('-');
                        }
                        try printLineNum(ctx, opts, cline_num);
                        try ctx.stdout.writeByte('-');

                        try ctx.stdout.writeAll(cline);
                    }

                    ctx.line_buf.clearRetainingCapacity();
                }

                // line prefix
                if (!opts.heading) {
                    try printPath(ctx, opts, path);
                    try ctx.stdout.writeByte(':');
                }
                try printLineNum(ctx, opts, line_num);
                try ctx.stdout.writeByte(':');

                line_has_match = true;
                file_has_match = true;
            }

            // print preceding text
            const preceding_text = line[line_pos..match.start];
            try ctx.stdout.writeAll(preceding_text);

            // print the match
            const match_text = line[match.start..match.end];
            if (opts.color) {
                try ctx.stdout.writeAll("\x1b[0m\x1b[1m\x1b[31m");
            }
            try ctx.stdout.writeAll(match_text);
            if (opts.color) {
                try ctx.stdout.writeAll("\x1b[0m");
            }

            line_pos = @intCast(match.end);
        }

        if (line_has_match) {
            // print remainder of line
            try ctx.stdout.print("{s}\n", .{line[line_pos..]});
            last_printed_line = line_num;
            after_context_lines = opts.after_context;
        } else if (after_context_lines > 0) {
            // print after context
            if (!opts.heading) {
                try printPath(ctx, opts, path);
                try ctx.stdout.writeByte('-');
            }
            try printLineNum(ctx, opts, line_num);
            try ctx.stdout.writeByte('-');

            try ctx.stdout.print("{s}\n", .{line});

            last_printed_line = line_num;
            after_context_lines -= 1;
        }

        chunk_buf.pos = end_pos;
        line_num += 1;
    }

    if (file_has_match and opts.heading) {
        try ctx.stdout.writeByte('\n');
    }
}

fn refillLineBuffer(chunk_buf: *ChunkBuffer, new_start_pos: usize) ![]const u8 {
    std.debug.assert(new_start_pos <= chunk_buf.pos);

    const num_reused_bytes = chunk_buf.end - new_start_pos;
    std.mem.copyForwards(u8, chunk_buf.items, chunk_buf.items[new_start_pos..chunk_buf.end]);
    chunk_buf.pos = chunk_buf.pos - new_start_pos;

    const len = try chunk_buf.reader.readAll(chunk_buf.items[num_reused_bytes..]);
    chunk_buf.end = num_reused_bytes + len;
    chunk_buf.is_last_chunk = chunk_buf.end < chunk_buf.items.len;

    return chunk_buf.items[0..chunk_buf.end];
}

inline fn printPath(ctx: *Context, opts: *const UserOptions, path: []const u8) !void {
    if (opts.color) {
        try ctx.stdout.writeAll("\x1b[35m");
    }
    try ctx.stdout.writeAll(path);
    if (opts.color) {
        try ctx.stdout.writeAll("\x1b[0m");
    }
}

inline fn printLineNum(ctx: *Context, opts: *const UserOptions, line_num: usize) !void {
    if (opts.color) {
        try ctx.stdout.writeAll("\x1b[32m");
    }
    try ctx.stdout.print("{}", .{line_num});
    if (opts.color) {
        try ctx.stdout.writeAll("\x1b[0m");
    }
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
) !u32 {
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

fn indexOfScalarPosRev(comptime T: type, slice: []const T, start_index: usize, value: T) ?usize {
    var i: usize = start_index;
    while (i > 0) {
        i -= 1;
        if (slice[i] == value) return i + 1;
    }
    return null;
}
