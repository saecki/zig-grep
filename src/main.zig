const c = @cImport({
    @cInclude("rure.h");
});

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Dir = std.fs.Dir;
const File = std.fs.File;
const IterableDir = std.fs.IterableDir;
const Stdout = File.Writer;

const args = @import("args.zig");

const TEXT_BUF_SIZE = 1 << 19;
const CHANNEL_BUF_SIZE = 1 << 6;

const PathSearchContext = struct {
    sink: *Sink,
    allocator: Allocator,
    regex: *c.rure,
    dir_stack: *ArrayList(StackEntry),
    name_buf: *ArrayList(u8),
};

pub const UserOptions = struct {
    before_context: u32 = 0,
    after_context: u32 = 0,
    color: bool = false,
    heading: bool = true,
    ignore_case: bool = false,
    follow_links: bool = false,
    hidden: bool = false,
    debug: bool = false,
    no_flush: bool = false,
    unicode: bool = true,
};

const StackEntry = struct {
    prev_dirname_len: usize,
    iter: IterableDir.Iterator,
};

/// Handle of the worker thread, and a channel to communicate with it.
const FileSearchWorker = struct {
    thread: std.Thread,
    channel_buf: []FileSearchWork,
    channel: std.event.Channel(FileSearchMessage),
};

/// The context inside the worker thread
const FileSearchContext = struct {
    sink: *Sink,
    allocator: Allocator,
    channel: std.event.Channel(FileSearchMessage),
    opts: *const UserOptions,
};

const FileSearchMessageType = enum {
    Some,
    Stop,
};
const FileSearchMessage = union(FileSearchMessageType) {
    Some: FileSearchWork,
    Stop: void,
};

// Ownership is transferred to the worker, so it is responsible for cleaning up the resources.
const FileSearchWork = struct {
    // Must be freed.
    path: []const u8,
    // Must be closed.
    file: File,
};

// Synchronizes output to the underlying writer, so files don't mix.
const Sink = struct {
    const Self = @This();

    fn writeByte(self: Self, byte: u8) !void {
        // TODO
        _ = self;
        _ = byte;
    }

    fn writeAll(self: Self, slice: []const u8) !void {
        // TODO
        _ = self;
        _ = slice;
    }

    fn print(self: Self, comptime format: []const u8, arg: anytype) !void {
        // TODO
        _ = arg;
        _ = format;
        _ = self;
    }
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
    var stdout_fd = std.io.getStdOut();
    defer stdout_fd.close();
    const stdout = stdout_fd.writer();

    run(stdout) catch |err| {
        if (err == error.Input) {
            try args.printHelp(stdout);
        } else if (err == error.Loop) {
            // print nothing
        } else {
            try stdout.print("{}\n", .{err});
        }

        return err;
    };
}

fn run(stdout: Stdout) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var opts = UserOptions{};
    var input_paths = ArrayList([]const u8).init(allocator);
    defer input_paths.deinit();
    const pattern = try args.parseArgs(stdout, &opts, &input_paths) orelse {
        return;
    };

    const regex = try compileRegex(stdout, &opts, pattern);
    defer c.rure_free(regex);

    var num_threads: usize = 4;
    if (std.Thread.getCpuCount()) |num_cpus| {
        num_threads = num_cpus;
    } else |e| {
        if (opts.debug) {
            try stdout.print("Couldn't get cpu count defaulting to {} thrads:\n{}\n", .{ num_threads, e });
        }
    }

    // synchronize writes stdout from this point on
    var sink = Sink{};
    var thread_pool = ArrayList(FileSearchWorker).init(allocator);
    defer thread_pool.deinit();
    try thread_pool.ensureTotalCapacity(num_threads);

    for (0..num_threads) |_| {
        const buffer = allocator.alloc(FileSearchMessage, CHANNEL_BUF_SIZE);
        errdefer allocator.free(buffer);
        const channel = std.event.Channel(FileSearchWork).init(buffer);

        const ctx = FileSearchContext{
            .sink = &sink,
            .allocator = allocator,
            .chanel = channel,
            .opts = &opts,
        };
        const thread = try std.Thread.spawn(.{}, consumeWork, .{ctx});
        const worker = FileSearchWorker{ .thread = thread, .channel = channel };
        try thread_pool.append(worker);
    }
    defer {
        for (thread_pool.items) |t| {
            t.channel.put(.Stop);
        }
        for (thread_pool.items) |t| {
            t.thread.join();
            allocator.free(t.buffer);
        }
    }

    var dir_stack = ArrayList(StackEntry).init(allocator);
    defer dir_stack.deinit();
    var name_buf = ArrayList(u8).init(allocator);
    defer name_buf.deinit();
    var ctx = PathSearchContext{
        .sink = &sink,
        .allocator = allocator,
        .regex = regex,
        .dir_stack = &dir_stack,
        .name_buf = &name_buf,
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

fn compileRegex(stdout: Stdout, opts: *const UserOptions, pattern: []const u8) !*c.rure {
    var regex_flags: u32 = 0;
    if (opts.ignore_case) {
        regex_flags |= c.RURE_FLAG_CASEI;
    }
    if (opts.unicode) {
        regex_flags |= c.RURE_FLAG_UNICODE;
    }

    var regex_error = c.rure_error_new();
    defer c.rure_error_free(regex_error);
    const maybe_regex = c.rure_compile(@ptrCast(pattern), pattern.len, regex_flags, null, regex_error);
    const regex = maybe_regex orelse {
        const error_message = c.rure_error_message(regex_error);
        try stdout.print("Error compiling pattern \"{s}\"\n{s}\n", .{ pattern, error_message });
        return error.Input;
    };

    return regex;
}

fn searchPath(
    ctx: *PathSearchContext,
    opts: *const UserOptions,
    input_path: ?[]const u8,
    abs_path: []const u8,
) (GrepError || ResourceError)!void {
    if (input_path) |p| {
        const open_flags = .{ .mode = .read_only };
        const file = try std.fs.openFileAbsolute(abs_path, open_flags);

        const stat = try file.stat();
        switch (stat.kind) {
            .file => {
                try enqueueWork(ctx, p, file);
                return;
            },
            .directory => {},
            .sym_link => {
                if (opts.follow_links) {
                    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    const link = try std.fs.readLinkAbsolute(abs_path, &link_buf);
                    try searchLink(ctx, opts, abs_path, "", link);
                } else if (opts.debug) {
                    try ctx.sink.print("Not following link: \"{s}\"\n", .{p});
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
                try ctx.sink.print("Not searching hidden path: \"{s}\"\n", .{ctx.name_buf.items});
            }
            continue;
        }

        switch (entry.kind) {
            .file => {
                const open_flags = .{ .mode = .read_only };
                var file = try current.iter.dir.openFile(entry.name, open_flags);
                try enqueueWork(ctx, ctx.name_buf.items, file);
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
                    try ctx.sink.print("Not following link: \"{s}\"\n", .{ctx.name_buf.items});
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
    ctx: *PathSearchContext,
    opts: *const UserOptions,
    abs_search_path: []const u8,
    sub_search_path: []const u8,
    link_path: []const u8,
) (GrepError || ResourceError)!void {
    // canonicalize path
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_link_path = try std.fs.realpath(link_path, &path_buf);

    if (symlinkLoops(abs_search_path, sub_search_path, abs_link_path)) {
        try ctx.sink.print("Loop detected \"{s}\" points to ancetor \"{s}\"\n", .{ sub_search_path, link_path });
        return error.Loop;
    }

    // the stack of searched directories
    var dir_stack = ArrayList(StackEntry).init(ctx.allocator);
    defer dir_stack.deinit();
    var name_buf = ArrayList(u8).init(ctx.allocator);
    defer name_buf.deinit();
    var new_ctx = PathSearchContext{
        .sink = ctx.sink,
        .allocator = ctx.allocator,
        .regex = ctx.regex,
        .dir_stack = &dir_stack,
        .name_buf = &name_buf,
    };

    try searchPath(&new_ctx, opts, link_path, abs_link_path);
}

/// Send work through a channel to a worker in `ctx.thread_pool`.
/// `path` is copied, and the responsibility of closing `file` is handed over.
fn enqueueWork(ctx: PathSearchContext, path: []const u8, file: File) !void {
    const owned_path = try ctx.allocator.alloc(u8, path.len);
    @memcpy(owned_path, path);

    const work = FileSearchWork{
        .path = owned_path,
        .file = file,
    };
    const msg = FileSearchMessage{ .Some = work };

    ctx.channel.put(msg);
}

fn consumeWork(ctx: FileSearchContext) !void {
    // reuse text buffer
    var text_buf = try ctx.allocator.alloc(u8, TEXT_BUF_SIZE);
    defer ctx.allocator.free(text_buf);
    var line_buf = ArrayList([]const u8).init(ctx.allocator);
    defer line_buf.deinit();
    try line_buf.ensureTotalCapacity(ctx.opts.before_context);

    while (true) {
        var msg = ctx.channel.get();
        switch (msg) {
            .Some => |work| {
                defer work.file.close();
                defer ctx.allocator.free(work.path);
                try searchFile(&ctx, text_buf, &line_buf, *work);
            },
            .Stop => break,
        }
    }
}

fn searchFile(
    ctx: *FileSearchContext,
    text_buf: []u8,
    line_buf: *ArrayList([]const u8),
    work: *FileSearchWork,
) !void {
    const opts = ctx.opts;
    const path = work.path;
    var file = work.file;
    var chunk_buf = ChunkBuffer{
        .reader = file.reader(),
        .items = text_buf,
        .pos = 0,
        .data_end = 0,
        .is_last_chunk = false,
    };

    var text = try refillChunkBuffer(&chunk_buf, 0);
    var file_has_match = false;
    var line_num: u32 = 1;
    var last_matched_line_num: ?u32 = null;
    var last_printed_line_num: ?u32 = null;

    // detect binary files
    const null_byte = std.mem.indexOfScalar(u8, text, 0x00);
    if (null_byte) |_| {
        return;
    }

    while (true) {
        var chunk_has_match = false;
        var line_iter = std.mem.splitScalar(u8, text[chunk_buf.pos..], '\n');
        var last_matched_line: ?[]const u8 = null;
        var printed_remainder = true;

        search: while (chunk_buf.pos < text.len) {
            var match: c.rure_match = undefined;
            const found = c.rure_find(ctx.regex, @ptrCast(text), text.len, chunk_buf.pos, &match);
            if (!found) {
                break;
            }

            // find current line (the containing this match)
            var current_line: []const u8 = undefined;
            var current_line_start: usize = undefined;
            while (line_iter.peek()) |line| {
                const line_start = textIndex(text, line);
                const line_end = line_start + line.len;
                if (line_start <= match.start and match.start <= line_end) {
                    // Some regex pattern may match newlines, which shouldn't be supported by default.
                    // If the match spans multiple lines, check if the first line would be enough to match.
                    if (match.end > line_end) {
                        const search_start = match.start;
                        const search_end = @min(line_end + 1, text.len);
                        const single_line_found = c.rure_find(ctx.regex, @ptrCast(text), search_end, search_start, &match);

                        if (!single_line_found) {
                            if (last_matched_line) |lml| {
                                if (!printed_remainder) {
                                    _ = try printRemainder(ctx.sink, &chunk_buf, text, lml);
                                    last_printed_line_num = last_matched_line_num;
                                    printed_remainder = true;
                                }
                            }

                            chunk_buf.pos = search_end;
                            continue :search;
                        }
                    }

                    current_line = line;
                    current_line_start = line_start;
                    break;
                }

                if (!printed_remainder) {
                    // remainder of last line
                    if (last_matched_line) |lml| {
                        chunk_buf.pos = try printRemainder(ctx.sink, &chunk_buf, text, lml);
                        last_printed_line_num = last_matched_line_num;
                        printed_remainder = true;
                    }
                }

                // after context lines
                if (last_matched_line_num) |lml_num| {
                    const is_after_context_line = line_num <= lml_num + opts.after_context;
                    const is_unprinted = last_printed_line_num orelse lml_num < line_num;
                    if (is_after_context_line and is_unprinted) {
                        try printLinePrefix(ctx.sink, opts, path, line_num, '-');
                        try ctx.sink.print("{s}\n", .{line});
                        chunk_buf.pos = @min(line_end + 1, text.len);
                        last_printed_line_num = line_num;
                    }
                }

                _ = line_iter.next();
                line_num += 1;
            } else {
                std.debug.panic("Didn't find line for match at text[{}..{}]\n", .{ match.start, match.end });
            }

            // heading
            if (!file_has_match and opts.heading) {
                if (opts.color) {
                    try ctx.sink.writeAll("\x1b[35m");
                }
                try ctx.sink.writeAll(path);
                if (opts.color) {
                    try ctx.sink.writeAll("\x1b[0m");
                }
                try ctx.sink.writeByte('\n');
            }

            const first_match_in_line = line_num != last_matched_line_num;
            if (first_match_in_line) {
                // non-contigous lines separator
                const lpl_num = last_printed_line_num orelse 0;
                const unprinted_before_lines = line_num - lpl_num - 1;
                if (opts.before_context > 0 or opts.after_context > 0) {
                    if (file_has_match and unprinted_before_lines > opts.before_context) {
                        try ctx.sink.writeAll("--\n");
                    }
                }

                // before context lines
                const before_context_lines = @min(opts.before_context, unprinted_before_lines);
                if (before_context_lines > 0) {
                    // collect lines
                    var cline_end = current_line_start;
                    for (0..before_context_lines) |_| {
                        var cline_start: u32 = 0;
                        if (cline_end > 1) {
                            if (indexOfScalarPosRev(u8, text, cline_end - 1, '\n')) |pos| {
                                cline_start = @intCast(pos);
                            }
                        }
                        const cline = text[cline_start..cline_end];
                        try line_buf.append(cline);

                        if (cline_start == 0) {
                            break;
                        }
                        cline_end = cline_start;
                    }

                    // print lines
                    var i: u32 = @truncate(line_buf.items.len);
                    while (i > 0) {
                        i -= 1;
                        const cline_num = line_num - i - 1;
                        const cline = line_buf.items[i];
                        try printLinePrefix(ctx.sink, opts, path, cline_num, '-');
                        try ctx.sink.writeAll(cline);
                    }

                    line_buf.clearRetainingCapacity();
                }

                try printLinePrefix(ctx.sink, opts, path, line_num, ':');

                chunk_has_match = true;
                file_has_match = true;
            }

            // preceding text
            const preceding_text_start = @max(current_line_start, chunk_buf.pos);
            const preceding_text = text[preceding_text_start..match.start];
            try ctx.sink.writeAll(preceding_text);

            // the match
            const match_text = text[match.start..match.end];
            if (opts.color) {
                try ctx.sink.writeAll("\x1b[0m\x1b[1m\x1b[31m");
            }
            try ctx.sink.writeAll(match_text);
            if (opts.color) {
                try ctx.sink.writeAll("\x1b[0m");
            }

            chunk_buf.pos = match.end;
            last_matched_line = current_line;
            last_matched_line_num = line_num;
            printed_remainder = false;
        }

        if (last_matched_line) |lml| {
            // remainder of last line
            if (!printed_remainder) {
                chunk_buf.pos = try printRemainder(ctx.sink, &chunk_buf, text, lml);
                last_printed_line_num = line_num;
                _ = line_iter.next();
                line_num += 1;
            }

            // after context lines
            const lml_num = last_matched_line_num.?;
            const unprinted_lines = (lml_num + opts.after_context + 1) -| line_num;
            const after_context_lines = @min(unprinted_lines, opts.after_context);
            for (0..after_context_lines) |_| {
                const cline = line_iter.next() orelse break;
                // ignore empty last line
                if (line_iter.peek() == null and cline.len == 0) {
                    break;
                }

                const cline_start = textIndex(text, cline);
                const cline_end = cline_start + cline.len;
                try printLinePrefix(ctx.sink, opts, path, line_num, '-');
                try ctx.sink.print("{s}\n", .{cline});

                chunk_buf.pos = @min(cline_end + 1, text.len);
                last_printed_line_num = line_num;
                line_num += 1;
            }
        }

        if (chunk_buf.is_last_chunk) {
            break;
        }

        // count remaining lines
        while (line_iter.next()) |l| {
            // ignore empty last line
            if (line_iter.peek() == null and l.len == 0) {
                break;
            }

            const line_start = textIndex(text, l);
            const line_end = line_start + l.len;
            chunk_buf.pos = @min(line_end + 1, text.len);
            line_num += 1;
        }

        // refill the buffer
        var new_start_pos = if (chunk_has_match) chunk_buf.pos else text.len;
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

        text = try refillChunkBuffer(&chunk_buf, new_start_pos);
    }

    if (file_has_match) {
        if (opts.heading) {
            try ctx.sink.writeByte('\n');
        }
        if (!opts.no_flush) {
            try ctx.sink.context.flush();
        }
    }
}

const ChunkBuffer = struct {
    reader: File.Reader,
    items: []u8,
    pos: usize,
    /// The end of data inside the chunk buffer, not the end of the text slice
    /// returned by refillChunkBuffer().
    data_end: usize,
    is_last_chunk: bool,
};

/// Moves the data after `new_start_pos` to the start of the internal buffer,
/// fills the remaining part of the buffer with data from `reader` and updates
/// `chunk_buf.pos`, `chunk_buf.data_end` and `chunk_buf.is_last_chunk`.
/// Then returns a slice of text from the start of the internal buffer until
/// the last line ending. Newlines are included if they are present.
inline fn refillChunkBuffer(chunk_buf: *ChunkBuffer, new_start_pos: usize) ![]const u8 {
    std.debug.assert(new_start_pos <= chunk_buf.pos);

    const num_reused_bytes = chunk_buf.data_end - new_start_pos;
    std.mem.copyForwards(u8, chunk_buf.items, chunk_buf.items[new_start_pos..chunk_buf.data_end]);
    chunk_buf.pos = chunk_buf.pos - new_start_pos;

    const len = try chunk_buf.reader.readAll(chunk_buf.items[num_reused_bytes..]);
    chunk_buf.data_end = num_reused_bytes + len;
    chunk_buf.is_last_chunk = chunk_buf.data_end < chunk_buf.items.len;

    var text_end = chunk_buf.data_end;
    if (!chunk_buf.is_last_chunk) {
        const last_line_end = indexOfScalarPosRev(u8, chunk_buf.items, chunk_buf.data_end, '\n');
        if (last_line_end) |end| {
            text_end = end;
        }
    }
    return chunk_buf.items[0..text_end];
}

inline fn textIndex(text: []const u8, slice_of_text: []const u8) usize {
    return @intFromPtr(slice_of_text.ptr) - @intFromPtr(text.ptr);
}

/// Searches backwards from the `start_index`, which is exclusive to the start of
/// the `slice` for the given scalar `value`. Returns the exclusive end position
/// of the first `value`.
///
/// See the test below for an example.
inline fn indexOfScalarPosRev(comptime T: type, slice: []const T, start_index: usize, value: T) ?usize {
    var i: usize = start_index;
    while (i > 0) {
        i -= 1;
        if (slice[i] == value) return i + 1;
    }
    return null;
}

test "exclusive index of scalar pos rev" {
    const slice = [_]u8{ 'a', 'b', 'c' };
    const pos = indexOfScalarPosRev(u8, &slice, slice.len, 'c').?;
    try std.testing.expectEqual(pos, 3);
}

inline fn printLinePrefix(sink: *Sink, opts: *const UserOptions, path: []const u8, line_num: u32, sep: u8) !void {
    if (!opts.heading) {
        // path
        if (opts.color) {
            try sink.writeAll("\x1b[35m");
        }
        try sink.writeAll(path);
        if (opts.color) {
            try sink.writeAll("\x1b[0m");
        }
        try sink.writeByte(sep);
    }

    // line number
    if (opts.color) {
        try sink.writeAll("\x1b[32m");
    }
    try sink.print("{}", .{line_num});
    if (opts.color) {
        try sink.writeAll("\x1b[0m");
    }
    try sink.writeByte(sep);
}

// Prints the remainder of `lml`. The remainder is found by comparing the `lml.ptr` with `text.ptr`.
// Returns the end of the line.
inline fn printRemainder(sink: *Sink, chunk_buf: *ChunkBuffer, text: []const u8, lml: []const u8) !usize {
    const lml_start = textIndex(text, lml);
    const lml_end = lml_start + lml.len;

    std.debug.assert(chunk_buf.pos <= lml_end);

    const remainder = text[chunk_buf.pos..lml_end];
    try sink.print("{s}\n", .{remainder});

    return @min(lml_end + 1, text.len);
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
