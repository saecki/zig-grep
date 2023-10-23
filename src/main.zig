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
const atomic = @import("atomic.zig");
const AtomicQueue = atomic.AtomicQueue;
const AtomicStack = atomic.AtomicStack;
const WalkerEntry = AtomicStack(DirIter).Entry;
const Sink = atomic.Sink;

const TEXT_BUF_SIZE = 1 << 19;
const SEACHER_QUEUE_BUF_SIZE = 1 << 8;

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

const WalkerContext = struct {
    allocator: Allocator,
    sink: *Sink,
    stack: *AtomicStack(DirIter),
    queue: *AtomicQueue(SearchWork),
    opts: *const UserOptions,
};

const DirIter = struct {
    path: DisplayPath,
    iter: IterableDir.Iterator,
};

/// The context inside the worker thread
const SearcherContext = struct {
    allocator: Allocator,
    sink: *Sink,
    queue: *AtomicQueue(SearchWork),
    regex: *c.rure,
    opts: *const UserOptions,
};

/// Ownership is transferred to the search worker, so it is responsible for cleaning up the resources.
const SearchWork = DisplayPath;
const DisplayPath = struct {
    /// Has to be freed by the worker.
    abs_path: []const u8,
    /// A path that the user provided, use this instead of absolute paths to make output more readable.
    display_path: ?[]const u8,
    /// Start offset of the subpath inside absolute paths.
    /// The subpath that can then be appended to the `display_path`.
    sub_path_offset: usize,
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

    var num_threads: u32 = 4;
    if (std.Thread.getCpuCount()) |num_cpus| {
        const n: u32 = @truncate(num_cpus);
        num_threads = @max(num_threads, n);
        if (opts.debug) {
            try stdout.print("Got cpu count {}\n", .{num_cpus});
        }
    } else |e| {
        if (opts.debug) {
            try stdout.print("Couldn't get cpu count defaulting to {} threads:\n{}\n", .{ num_threads, e });
        }
    }
    const num_walkers = @max(2, num_threads / 4);
    const num_searchers = num_threads - num_walkers;

    // synchronize writes to stdout from here on
    var sink = Sink.init(stdout);

    // start searcher threads
    var queue_buf = try allocator.alloc(SearchWork, SEACHER_QUEUE_BUF_SIZE);
    defer allocator.free(queue_buf);
    var queue = AtomicQueue(SearchWork).init(queue_buf);
    var searchers = ArrayList(std.Thread).init(allocator);
    defer searchers.deinit();
    try searchers.ensureTotalCapacity(num_threads);
    for (0..num_searchers) |_| {
        const ctx = SearcherContext{
            .allocator = allocator,
            .sink = &sink,
            .queue = &queue,
            .regex = regex,
            .opts = &opts,
        };
        const thread = try std.Thread.spawn(.{}, startSearcher, .{ctx});
        try searchers.append(thread);
    }
    defer {
        queue.stop();
        for (searchers.items) |t| {
            t.join();
        }
    }

    // fill stack initially
    var stack_buf = ArrayList(WalkerEntry).init(allocator);
    defer stack_buf.deinit();
    if (input_paths.items.len == 0) {
        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const abs_path = try std.fs.realpath(".", &path_buf);
        var owned_abs_path = try allocator.alloc(u8, abs_path.len);
        @memcpy(owned_abs_path, abs_path);
        const path = DisplayPath{
            .abs_path = owned_abs_path,
            .display_path = null,
            .sub_path_idx = abs_path.len,
        };

        const open_options = .{ .no_follow = true };
        const dir = try std.fs.openIterableDirAbsolute(abs_path, open_options);
        stack_buf.append(WalkerEntry{
            .depth = 0,
            .data = DirIter{
                .iter = dir.iterate(),
                .path = path,
            },
        });
    } else {
        for (input_paths.items) |input_path| {
            var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const abs_path = try std.fs.realpath(input_path, &path_buf);
            var owned_abs_path = try allocator.alloc(u8, abs_path.len);
            @memcpy(owned_abs_path, abs_path);
            const path = DisplayPath{
                .abs_path = abs_path,
                .display_path = input_path,
                .sub_path_idx = abs_path.len,
            };

            const dir_iter = getDirIterOrEnqueue(&sink, &queue, &opts, path);
            if (dir_iter) |d| {
                stack_buf.append(WalkerEntry{
                    .depth = 0,
                    .data = d,
                });
            }
        }
    }

    // start walker threads only if necessary
    if (stack_buf.items.len == 0) {
        return;
    }

    var stack = AtomicStack(DirIter).init(allocator, num_walkers);
    defer stack.deinit();
    var walkers = ArrayList(std.Thread).init(allocator);
    defer walkers.deinit();
    try walkers.ensureTotalCapacity(num_threads);
    for (0..num_walkers) |_| {
        const ctx = WalkerContext{
            .allocator = allocator,
            .sink = &sink,
            .stack = &stack,
            .queue = &queue,
            .opts = &opts,
        };
        const thread = try std.Thread.spawn(.{}, startWalker, .{ctx});
        try walkers.append(thread);
    }
    for (walkers.items) |t| {
        t.join();
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

fn startWalker(_ctx: WalkerContext) !void {
    // make ctx mutable
    var ctx = _ctx;

    var path_buf = ArrayList(u8).init(ctx.allocator);
    defer path_buf.deinit();

    while (true) {
        const msg = ctx.stack.pop();
        switch (msg) {
            .Some => |entry| {
                try walkPath(ctx, entry);
            },
            .Stop => break,
        }
    }
}

fn walkPath(
    ctx: *WalkerContext,
    path_buf: *ArrayList(u8),
    _entry: WalkerEntry,
) (GrepError || ResourceError)!void {
    const opts = ctx.opts;
    
    var entry = _entry;
    var dir_path = entry.data.path;

    path_buf.clearRetainingCapacity();
    path_buf.appendSlice(dir_path.abs_path);
    if (dir_path.abs_path.len > 0 and dir_path.abs_path[dir_path.abs_path.len - 1] != std.fs.path.sep) {
        path_buf.append(std.fs.path.sep);
    }
    var dirname_len = path_buf.items.len;

    while (true) {
        const e = entry.data.iter.next() orelse {
            try ctx.allocator.free(dir_path.abs_path);
            entry.data.iter.dir.close();
            break;
        };

        // skip hidden files
        if (!opts.hidden and e.name[0] == '.') {
            if (opts.debug) {
                try ctx.sink.print("Not searching hidden path: \"{s}\"\n", .{ctx.name_buf.items});
            }
            continue;
        }

        path_buf.shrinkRetainingCapacity(dirname_len);
        path_buf.appendSlice(e.name);

        switch (e.kind) {
            .file => {
                enqueueWork(ctx, path_buf.items, dir_path.display_path, dir_path.sub_path_idx);
            },
            .directory => {
                const open_options = .{ .no_follow = true };
                var abs_path = try ctx.allocator.alloc(u8, dir_path.abs_path.len);
                @memcpy(abs_path, path_buf.items);

                const sub_dir = try std.fs.openIterableDirAbsolute(abs_path, open_options);
                const sub_dir_path = DisplayPath{
                    .abs_path = abs_path,
                    .display_path = dir_path.display_path,
                    .sub_path_offset = dir_path.sub_path_offset,
                };
                const sub_dir_entry = WalkerEntry{
                    .depth = entry.depth + 1,
                    .data = DirIter{
                        .iter = sub_dir.iterate(),
                        .path = sub_dir_path,
                    },
                };

                // put back dir iter on the stack, and traverse depth first
                ctx.stack.push(entry);

                path_buf.append(std.fs.path.sep);
                dirname_len = path_buf.items.len;
                entry = sub_dir_entry;
                dir_path = sub_dir_entry.data.path;
            },
            .sym_link => {
                if (opts.follow_links) {
                    var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                    const link = try std.fs.readLinkAbsolute(dir_path.abs_path, &link_buf);
                    _ = link;
                    // TODO: search link
                } else if (opts.debug) {
                    try ctx.sink.writeAll("Not following link: \"");
                    printPath(ctx.sink, &dir_path);
                    try ctx.sink.writeAll("\"\n");
                }
            },
            // ignore
            .block_device, .character_device, .named_pipe, .unix_domain_socket, .whiteout, .door, .event_port, .unknown => {},
        }
    }
}

inline fn getDirIterOrEnqueue(sink: *Sink, queue: *AtomicQueue(SearchWork), opts: *const UserOptions, path: DisplayPath) !?DirIter {
    const open_flags = .{ .mode = .read_only };
    const file = try std.fs.openFileAbsolute(path.abs_path, open_flags);

    const stat = try file.stat();
    switch (stat.kind) {
        .file => {
            file.close();
            queue.append(path);
        },
        .directory => {
            file.close();
            const open_options = .{ .no_follow = true };
            const dir = try std.fs.openIterableDirAbsolute(path.abs_path, open_options);
            return DirIter{
                .iter = dir.iterate(),
                .path = path,
            };
        },
        .sym_link => {
            file.close();
            if (opts.follow_links) {
                var link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                const link = try std.fs.readLinkAbsolute(path.abs_path, &link_buf);
                _ = link;
                // TODO: search link
            } else if (opts.debug) {
                try sink.writeAll("Not following link: \"");
                printPath(sink, &path);
                try sink.writeAll("\"\n");
            }
        },
        // ignore
        .block_device, .character_device, .named_pipe, .unix_domain_socket, .whiteout, .door, .event_port, .unknown => {
            file.close();
        },
    }

    return null;
}

/// `link_path` is the dereferenced link.
fn searchLink(
    ctx: *WalkerContext,
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
    var dir_stack = ArrayList(WalkerEntry).init(ctx.allocator);
    defer dir_stack.deinit();
    var name_buf = ArrayList(u8).init(ctx.allocator);
    defer name_buf.deinit();
    var new_ctx = WalkerContext{
        .allocator = ctx.allocator,
        .sink = ctx.sink,
        .queue = ctx.queue,
        .dir_stack = &dir_stack,
        .name_buf = &name_buf,
    };

    try walkPath(&new_ctx, opts, null, abs_link_path);
}

/// Send work through a queue to a worker in `ctx.thread_pool`.
/// `path` is copied, and the responsibility of closing `file` is handed over.
fn enqueueWork(ctx: *WalkerContext, abs_path: []const u8, display_path: ?[]const u8, sub_path_idx: usize) !void {
    const owned_abs_path = try ctx.allocator.alloc(u8, abs_path.len);
    @memcpy(owned_abs_path, abs_path);

    const work = SearchWork{
        .abs_path = owned_abs_path,
        .display_path = display_path,
        .sub_path_idx = sub_path_idx,
    };
    ctx.queue.append(work);
}

fn startSearcher(_ctx: SearcherContext) !void {
    // make ctx mutable
    var ctx = _ctx;

    // reuse text buffer
    var text_buf = try ctx.allocator.alloc(u8, TEXT_BUF_SIZE);
    defer ctx.allocator.free(text_buf);
    var line_buf = ArrayList([]const u8).init(ctx.allocator);
    defer line_buf.deinit();
    try line_buf.ensureTotalCapacity(ctx.opts.before_context);

    while (true) {
        var msg = ctx.queue.get();
        switch (msg) {
            .Some => |work| {
                defer ctx.allocator.free(work.abs_path);
                try searchFile(&ctx, text_buf, &line_buf, &work);
            },
            .Stop => break,
        }
    }
}

fn searchFile(
    ctx: *SearcherContext,
    text_buf: []u8,
    line_buf: *ArrayList([]const u8),
    work: *const SearchWork,
) !void {
    const open_flags = .{ .mode = .read_only };
    const file = try std.fs.openFileAbsolute(work.abs_path, open_flags);
    defer file.close();

    const opts = ctx.opts;
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
                        try printLinePrefix(ctx.sink, opts, work, line_num, '-');
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
                try printPath(ctx.sink, work);
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
                        try printLinePrefix(ctx.sink, opts, work, cline_num, '-');
                        try ctx.sink.writeAll(cline);
                    }

                    line_buf.clearRetainingCapacity();
                }

                try printLinePrefix(ctx.sink, opts, work, line_num, ':');

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
                try printLinePrefix(ctx.sink, opts, work, line_num, '-');
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
            try ctx.sink.flush();
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

inline fn printLinePrefix(sink: *Sink, opts: *const UserOptions, work: *const SearchWork, line_num: u32, sep: u8) !void {
    if (!opts.heading) {
        // path
        if (opts.color) {
            try sink.writeAll("\x1b[35m");
        }
        if (work.display_path) |p| {
            try sink.writeAll(p);
        }
        try sink.writeAll(work.abs_path[work.sub_path_idx..]);
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

inline fn printPath(sink: *Sink, work: *const DisplayPath) !void {
    const sub_path = work.abs_path[work.sub_path_idx..];
    if (work.display_path) |p| {
        try sink.writeAll(p);
        if (sub_path.len > 0 and p.len > 0 and p[p.len - 1] != std.fs.path.sep) {
            try sink.writeByte(std.fs.path.sep);
        }
    }
    try sink.writeAll(sub_path);
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
