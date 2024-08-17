const c = @cImport({
    @cInclude("rure.h");
});

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Dir = std.fs.Dir;
const File = std.fs.File;
const Stdout = File.Writer;

const args = @import("args.zig");
const UserOptions = args.UserOptions;
const atomic = @import("atomic.zig");
const AtomicStack = atomic.AtomicStack;
const WalkerEntry = AtomicStack(DirIter).Entry;
const Sink = atomic.Sink;
const SinkBuf = atomic.SinkBuf;

const TEXT_BUF_SIZE = 1 << 16;
const SINK_BUF_SIZE = 1 << 12;

const DIR_OPEN_OPTIONS = Dir.OpenDirOptions{
    .iterate = true,
    .no_follow = true,
};
const FILE_OPEN_FLAGS = File.OpenFlags{
    .mode = .read_only,
};

const Params = struct {
    regex: *c.rure,
    opts: *const UserOptions,
    input_paths: []const []const u8,
};

const WorkerContext = struct {
    allocator: Allocator,
    stack: *AtomicStack(DirIter),
    sink: SinkBuf,
    regex: *c.rure,
    opts: *const UserOptions,
    input_paths: []const []const u8,
};

const DirIter = struct {
    /// abs path has to be freed by the worker.
    path: DisplayPath,
    iter: Dir.Iterator,
};

/// Ownership is transferred to the search worker, so it is responsible for cleaning up the resources.
const DisplayPath = struct {
    abs: []const u8,
    /// An index of a path that the user provided, use this as a prefix to make output more readable.
    display_prefix: ?u16,
    /// Start offset of the subpath inside the `abs` path.
    /// The subpath that can then be appended to the `display_prefix`.
    sub_path_offset: u16,
};

const GrepError = error{
    Input,
    Loop,
};

const ResourceError = error{
    AccessDenied,
    AntivirusInterference,
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
    InvalidUtf8,
    InvalidWtf8,
    IsDir,
    LockViolation,
    NameTooLong,
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
    SocketNotConnected,
    SymLinkLoop,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
    UnrecognizedVolume,
    UnsupportedReparsePointType,
    WouldBlock,

    // io_uring
    BufferInvalid,
    CompletionQueueOvercommitted,
    FileDescriptorInBadState,
    FileDescriptorInvalid,
    OpcodeNotSupported,
    RingShuttingDown,
    SignalInterrupt,
    SubmissionQueueEntryInvalid,
    SubmissionQueueFull,

    // returned when the res field of an cqe is negative (contains the negative errno).
    IoUring,
};

pub fn main() void {
    wrapRun() catch {
        std.process.exit(1);
    };
}

fn wrapRun() !void {
    var stdout_fd = std.io.getStdOut();
    defer stdout_fd.close();
    const stdout = stdout_fd.writer();

    run(stdout) catch |err| {
        if (err == error.Input) {
            try stdout.writeByte('\n');
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

    // synchronize writes to stdout from here on
    var sink = Sink.init(stdout);

    // fill stack initially
    var stack_buf = ArrayList(WalkerEntry).init(allocator);
    defer stack_buf.deinit();
    if (input_paths.items.len == 0) {
        var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const abs_path = try std.fs.realpath(".", &path_buf);
        const path = DisplayPath{
            .abs = abs_path,
            .display_prefix = null,
            .sub_path_offset = @truncate(abs_path.len),
        };

        const dir = try std.fs.openDirAbsolute(abs_path, DIR_OPEN_OPTIONS);
        try stack_buf.append(WalkerEntry{
            .priority = 0,
            .data = DirIter{
                .iter = dir.iterate(),
                .path = path,
            },
        });
    } else {
        const buf = try allocator.alloc(u8, SINK_BUF_SIZE);
        defer allocator.free(buf);
        var sink_buf = SinkBuf.init(&sink, buf);

        const text_buf = try allocator.alloc(u8, TEXT_BUF_SIZE);
        defer allocator.free(text_buf);
        var line_buf = ArrayList([]const u8).init(allocator);
        defer line_buf.deinit();
        try line_buf.ensureTotalCapacity(opts.before_context);

        const params = Params{
            .regex = regex,
            .opts = &opts,
            .input_paths = input_paths.items,
        };
        for (input_paths.items, 0..) |input_path, i| {
            var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const abs_path = try std.fs.realpath(input_path, &path_buf);
            const path = DisplayPath{
                .abs = abs_path,
                .display_prefix = @truncate(i),
                .sub_path_offset = @truncate(abs_path.len),
            };
            // TODO
            var ring: Ring = undefined;

            const dir_iter = try getDirIterOrSearch(allocator, &ring, &line_buf, &sink_buf, &params, path);
            if (dir_iter) |d| {
                try stack_buf.append(WalkerEntry{
                    .priority = 0,
                    .data = d,
                });
            }
        }
    }

    // start walker threads only if necessary
    if (stack_buf.items.len == 0) {
        return;
    }
    // start worker threads
    var group = std.Thread.WaitGroup{};
    var stack = AtomicStack(DirIter).init(&stack_buf, num_threads);
    for (0..num_threads) |_| {
        const buf = try allocator.alloc(u8, SINK_BUF_SIZE);
        const sink_buf = SinkBuf.init(&sink, buf);
        const ctx = WorkerContext{
            .allocator = allocator,
            .stack = &stack,
            .sink = sink_buf,
            .regex = regex,
            .opts = &opts,
            .input_paths = input_paths.items,
        };
        group.start();
        _ = try std.Thread.spawn(.{}, startWorker, .{ &group, ctx });
    }
    group.wait();
}

fn compileRegex(stdout: Stdout, opts: *const UserOptions, pattern: []const u8) !*c.rure {
    var regex_flags: u32 = 0;
    if (opts.ignore_case) {
        regex_flags |= c.RURE_FLAG_CASEI;
    }
    if (opts.unicode) {
        regex_flags |= c.RURE_FLAG_UNICODE;
    }

    const regex_error = c.rure_error_new();
    defer c.rure_error_free(regex_error);
    const maybe_regex = c.rure_compile(@ptrCast(pattern), pattern.len, regex_flags, null, regex_error);
    const regex = maybe_regex orelse {
        const error_message = c.rure_error_message(regex_error);
        try stdout.print("Error compiling pattern \"{s}\"\n{s}\n", .{ pattern, error_message });
        return error.Input;
    };

    return regex;
}

fn startWorker(group: *std.Thread.WaitGroup, ctx: WorkerContext) !void {
    defer group.finish();

    var allocator = ctx.allocator;
    var stack = ctx.stack;
    var sink = ctx.sink;
    defer allocator.free(sink.buf);
    const params = Params{
        .regex = ctx.regex,
        .opts = ctx.opts,
        .input_paths = ctx.input_paths,
    };

    // reuse buffers
    var path_buf = ArrayList(u8).init(ctx.allocator);
    defer path_buf.deinit();
    const text_buf = try allocator.alloc(u8, TEXT_BUF_SIZE);
    defer allocator.free(text_buf);
    var line_buf = ArrayList([]const u8).init(allocator);
    defer line_buf.deinit();
    try line_buf.ensureTotalCapacity(params.opts.before_context);

    var ring = try Ring.init(allocator);
    defer ring.deinit();
    try ring.setup();

    while (true) {
        const msg = stack.pop();
        switch (msg) {
            .Some => |entry| {
                try walkPath(allocator, stack, &ring, text_buf, &line_buf, &sink, &params, &path_buf, entry);
            },
            .Stop => break,
        }
    }
}

const IO_URING_BUF_SIZE = 1 << 1;
const Ring = struct {
    ring: std.os.linux.IoUring,
    /// external queue for CQEs that should be handled later
    queue: [IO_URING_BUF_SIZE]Cqe = undefined,
    queue_start: usize = 0,
    queue_end: usize = 0,

    /// memory area that the `std.posix.iovec`s point to
    text_base_buf: []u8,
    text_bufs: [IO_URING_BUF_SIZE]std.posix.iovec,
    paths: [IO_URING_BUF_SIZE]DisplayPath = undefined,
    used_mask: u8 = 0,

    allocator: Allocator,

    const Self = @This();

    fn init(allocator: Allocator) !Self {
        const flags = 0; // std.os.linux.IORING_FEAT_RW_CUR_POS | std.os.linux.IORING_FEAT_RSRC_TAGS;
        const io_uring = try std.os.linux.IoUring.init(IO_URING_BUF_SIZE, flags);
        const text_base_buf = try allocator.alloc(u8, IO_URING_BUF_SIZE * TEXT_BUF_SIZE);
        var text_bufs: [IO_URING_BUF_SIZE]std.posix.iovec = undefined;
        for (0..IO_URING_BUF_SIZE) |i| {
            text_bufs[i].base = text_base_buf.ptr + i * TEXT_BUF_SIZE;
            text_bufs[i].len = TEXT_BUF_SIZE;
        }
        const self = Self{
            .ring = io_uring,
            .text_base_buf = text_base_buf,
            .text_bufs = text_bufs,
            .allocator = allocator,
        };

        return self;
    }

    /// The `Ring` can't be moved once this has been called.
    fn setup(self: *Self) !void {
        const fds = [1]std.os.linux.fd_t{-1} ** IO_URING_BUF_SIZE;
        try self.ring.register_files(&fds);
        try self.ring.register_buffers(&self.text_bufs);
    }

    fn deinit(self: *Self) void {
        self.ring.deinit();
        self.allocator.free(self.text_base_buf);
    }

    fn availableBufIdx(self: *const Self) ?u8 {
        // trailing zero of bitwise inverse
        // => trailing ones
        // => first zero
        const idx = @ctz(~self.used_mask);
        if (idx < IO_URING_BUF_SIZE) {
            return @intCast(idx);
        }
        return null;
    }

    fn numFilesInUse(self: *const Self) u8 {
        return @popCount(self.used_mask);
    }

    fn useBufIdx(self: *Self, idx: u8) void {
        self.used_mask |= @as(u8, 1) << @truncate(idx);
    }

    fn returnBufIdx(self: *Self, idx: u8) void {
        self.used_mask &= ~(@as(u8, 1) << @truncate(idx));
    }

    fn cqeAvailable(self: *Self) bool {
        return (self.queue_end - self.queue_start) > 0 or self.ring.cq_ready() > 0;
    }

    /// returns a slice equivalent to the iovec at `idx` inside `text_bufs`
    fn textBuf(self: *Self, idx: u8) []u8 {
        return self.text_base_buf[@as(u64, idx) * TEXT_BUF_SIZE ..][0..TEXT_BUF_SIZE];
    }
};

fn walkPath(
    allocator: Allocator,
    stack: *AtomicStack(DirIter),
    ring: *Ring,
    text_buf: []u8,
    line_buf: *ArrayList([]const u8),
    sink: *SinkBuf,
    params: *const Params,
    path_buf: *ArrayList(u8),
    _dir_entry: WalkerEntry,
) (GrepError || ResourceError)!void {
    var dir_entry = _dir_entry;
    var dir_path = dir_entry.data.path;

    path_buf.clearRetainingCapacity();
    try path_buf.appendSlice(dir_path.abs);
    if (dir_path.abs.len > 0 and dir_path.abs[dir_path.abs.len - 1] != std.fs.path.sep) {
        try path_buf.append(std.fs.path.sep);
    }
    var dirname_len = path_buf.items.len;

    while (true) {
        // only look at new entries while the io_uring queue is non-full
        if (ring.availableBufIdx()) |buf_idx| {
            const e = try dir_entry.data.iter.next() orelse {
                allocator.free(dir_path.abs);
                dir_entry.data.iter.dir.close();
                break;
            };

            path_buf.shrinkRetainingCapacity(dirname_len);
            try path_buf.appendSlice(e.name);

            // skip hidden files
            if (!params.opts.hidden and e.name[0] == '.') {
                if (params.opts.debug) {
                    try sink.writeAll("Not searching hidden path: \"");
                    try printPath(sink, params.input_paths, &DisplayPath{
                        .abs = path_buf.items,
                        .display_prefix = dir_path.display_prefix,
                        .sub_path_offset = dir_path.sub_path_offset,
                    });
                    try sink.writeAll("\"\n");
                    try sink.end();
                }
                continue;
            }

            switch (e.kind) {
                .file => {
                    const owned_abs_path = try allocSlice(u8, ring.allocator, path_buf.items);
                    ring.paths[buf_idx] = DisplayPath{
                        .abs = owned_abs_path,
                        .display_prefix = dir_path.display_prefix,
                        .sub_path_offset = dir_path.sub_path_offset,
                    };
                    ring.useBufIdx(buf_idx);

                    const user_data = toUserData(.{ .OpenFile = .{ .buf_idx = buf_idx } });
                    const dir_fd = std.fs.cwd().fd;
                    const pathz = try std.posix.toPosixPath(path_buf.items);
                    const flags = std.os.linux.O{ .NOFOLLOW = true };
                    const mode: std.os.linux.mode_t = 1 << 2; // READONLY
                    const file_index = std.os.linux.IORING_FILE_INDEX_ALLOC;
                    _ = try ring.ring.openat_direct(user_data, dir_fd, &pathz, flags, mode, file_index);
                    _ = try ring.ring.submit();
                },
                .directory => {
                    const owned_abs_path = try allocSlice(u8, allocator, path_buf.items);

                    const sub_dir = try std.fs.openDirAbsolute(owned_abs_path, DIR_OPEN_OPTIONS);
                    const sub_dir_path = DisplayPath{
                        .abs = owned_abs_path,
                        .display_prefix = dir_path.display_prefix,
                        .sub_path_offset = dir_path.sub_path_offset,
                    };
                    const sub_dir_entry = WalkerEntry{
                        .priority = dir_entry.priority + 1,
                        .data = DirIter{
                            .iter = sub_dir.iterate(),
                            .path = sub_dir_path,
                        },
                    };

                    // put back dir iter on the stack, and traverse depth first
                    try stack.push(dir_entry);

                    try path_buf.append(std.fs.path.sep);
                    dirname_len = path_buf.items.len;
                    dir_entry = sub_dir_entry;
                    dir_path = sub_dir_entry.data.path;
                },
                .sym_link => {
                    if (params.opts.follow_links) {
                        const link_file_path = DisplayPath{
                            .abs = path_buf.items,
                            .display_prefix = dir_path.display_prefix,
                            .sub_path_offset = dir_path.sub_path_offset,
                        };
                        const dir_iter = try walkLink(allocator, ring, line_buf, sink, params, link_file_path);
                        if (dir_iter) |d| {
                            const link_dir_entry = WalkerEntry{
                                .priority = dir_entry.priority + 1,
                                .data = d,
                            };
                            try stack.push(link_dir_entry);
                        }
                    } else if (params.opts.debug) {
                        try sink.writeAll("Not following link: \"");
                        try printPath(sink, params.input_paths, &dir_path);
                        try sink.writeAll("\"\n");
                        try sink.end();
                    }
                },
                // ignore
                .block_device, .character_device, .named_pipe, .unix_domain_socket, .whiteout, .door, .event_port, .unknown => {},
            }

            if (ring.cqeAvailable()) {
                try handleCqe(ring, text_buf, line_buf, sink, params);
            }
        } else {
            try handleCqe(ring, text_buf, line_buf, sink, params);
        }
    }

    while (ring.numFilesInUse() > 0) {
        try handleCqe(ring, text_buf, line_buf, sink, params);
    }
}

const OpKind = enum(u8) {
    OpenFile = 1,
    ReadFile = 2,
    CloseFile = 3,
};

// stored inside the `user_data` field of io_uring SQE and CQE
const OpUserData = union(OpKind) {
    OpenFile: OpenFile,
    ReadFile: ReadFile,
    CloseFile: ReadFile,
};

const OpenFile = struct {
    buf_idx: u8,
};

const ReadFile = struct {
    /// this is not a normal 32-bit file descriptor, but an index into the direct file descriptor
    /// array managed by io_uring.
    fd: u8,
    buf_idx: u8,
};

fn toUserData(op: OpUserData) u64 {
    const op_kind: OpKind = op;
    const kind = @intFromEnum(op_kind);
    switch (op) {
        .OpenFile => |f| {
            return (@as(u64, f.buf_idx) << 8) | @as(u64, kind);
        },
        .ReadFile, .CloseFile => |f| {
            const fd: u64 = @intCast(f.fd);
            return (fd << 16) | (@as(u64, f.buf_idx) << 8) | @as(u64, kind);
        },
    }
}

fn fromUserData(user_data: u64) OpUserData {
    const kind: OpKind = @enumFromInt(user_data & 0xFF);
    return switch (kind) {
        .OpenFile => .{ .OpenFile = .{
            .buf_idx = @truncate((user_data >> 8) & 0xFF),
        } },
        .ReadFile => .{ .ReadFile = .{
            .buf_idx = @truncate((user_data >> 8) & 0xFF),
            .fd = @intCast((user_data >> 16) & 0xFF),
        } },
        .CloseFile => .{ .CloseFile = .{
            .buf_idx = @truncate((user_data >> 8) & 0xFF),
            .fd = @intCast((user_data >> 16) & 0xFF),
        } },
    };
}

test "io_uring user_data conversion open file" {
    const expected = OpUserData{ .OpenFile = .{ .buf_idx = 3 } };
    const user_data = toUserData(expected);
    const actual = fromUserData(user_data);
    try std.testing.expectEqual(expected, actual);
}

test "io_uring user_data conversion read file" {
    const expected = OpUserData{ .ReadFile = .{ .buf_idx = 3, .fd = 2 } };
    const user_data = toUserData(expected);
    const actual = fromUserData(user_data);
    try std.testing.expectEqual(expected, actual);
}

test "io_uring user_data conversion close file" {
    const expected = OpUserData{ .CloseFile = .{ .buf_idx = 3, .fd = 2 } };
    const user_data = toUserData(expected);
    const actual = fromUserData(user_data);
    try std.testing.expectEqual(expected, actual);
}

fn handleCqe(
    ring: *Ring,
    text_buf: []u8,
    line_buf: *ArrayList([]const u8),
    sink: *SinkBuf,
    params: *const Params,
) !void {
    const cqe = try nextQueuedCqe(ring);
    switch (cqe.op) {
        .OpenFile => |f| {
            const fd: u8 = @truncate(cqe.res);
            const read_op = .{ .ReadFile = .{ .buf_idx = f.buf_idx, .fd = fd } };
            const user_data = toUserData(read_op);

            const buffer = &ring.text_bufs[f.buf_idx];
            const file_offset: u64 = @bitCast(@as(i64, -1)); // just continue reading at the last position
            const sqe = try ring.ring.read_fixed(user_data, fd, buffer, file_offset, f.buf_idx);
            sqe.flags |= std.os.linux.IOSQE_FIXED_FILE;
            _ = try ring.ring.submit();
        },
        .ReadFile => |f| {
            const len: usize = @intCast(cqe.res);
            try searchFile(ring, text_buf, line_buf, sink, params, f, len);
        },
        .CloseFile => |f| {
            ring.returnBufIdx(f.buf_idx);
        },
    }
}

const Cqe = struct {
    op: OpUserData,
    // unsigned, because it has already been checked for errors
    res: u32,
    flags: u32,
};

fn nextQueuedCqe(ring: *Ring) !Cqe {
    if (ring.queue_end - ring.queue_start > 0) {
        const cqe = ring.queue[ring.queue_start % IO_URING_BUF_SIZE];
        ring.queue_start += 1;
        return cqe;
    }

    return nextNewCqe(ring);
}

fn nextNewCqe(ring: *Ring) !Cqe {
    const cqe = try ring.ring.copy_cqe();
    if (cqe.res < 0) {
        return error.IoUring;
    }
    const res: u32 = @intCast(cqe.res);
    const op = fromUserData(cqe.user_data);
    const ret = .{ .op = op, .res = res, .flags = cqe.flags };
    return ret;
}

fn walkLink(
    allocator: Allocator,
    ring: *Ring,
    line_buf: *ArrayList([]const u8),
    sink: *SinkBuf,
    params: *const Params,
    link_file_path: DisplayPath,
) (GrepError || ResourceError)!?DirIter {
    var rel_link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const rel_link_path = try std.fs.readLinkAbsolute(link_file_path.abs, &rel_link_buf);

    // realpath needs to know the location of the link file to correctly canonicalize `.` or `..`.
    const dir_end = indexOfScalarPosRev(u8, link_file_path.abs, link_file_path.abs.len, '/') orelse std.debug.panic("Couldn't find dir of \"{s}\"\n", .{link_file_path.abs});
    const dir_path = link_file_path.abs[0..dir_end];
    const dir = try std.fs.openDirAbsolute(dir_path, DIR_OPEN_OPTIONS);

    var abs_link_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_link_path = try dir.realpath(rel_link_path, &abs_link_buf);

    const link_path = DisplayPath{
        .abs = abs_link_path,
        .display_prefix = null,
        .sub_path_offset = 0,
    };

    if (symlinkLoops(link_file_path.abs, abs_link_path)) {
        try sink.writeAll("Loop detected \"");
        try printPath(sink, params.input_paths, &link_file_path);
        try sink.writeAll("\" points to ancestor \"");
        try printPath(sink, params.input_paths, &link_path);
        try sink.writeAll("\"\n");
        try sink.end();

        return error.Loop;
    }

    return getDirIterOrSearch(allocator, ring, line_buf, sink, params, link_path);
}

inline fn getDirIterOrSearch(
    allocator: Allocator,
    ring: *Ring,
    line_buf: *ArrayList([]const u8),
    sink: *SinkBuf,
    params: *const Params,
    path: DisplayPath,
) !?DirIter {
    const stat = try std.fs.cwd().statFile(path.abs);
    switch (stat.kind) {
        .file => {
            // TODO
            // try searchFile(text_buf, line_buf, sink, params, file, &path);
        },
        .directory => {
            const dir = try std.fs.openDirAbsolute(path.abs, DIR_OPEN_OPTIONS);

            const owned_abs_path = try allocSlice(u8, allocator, path.abs);
            const owned_path = DisplayPath{
                .abs = owned_abs_path,
                .display_prefix = path.display_prefix,
                .sub_path_offset = path.sub_path_offset,
            };
            return DirIter{
                .iter = dir.iterate(),
                .path = owned_path,
            };
        },
        .sym_link => {
            if (params.opts.follow_links) {
                return walkLink(allocator, ring, line_buf, sink, params, path);
            } else if (params.opts.debug) {
                try sink.writeAll("Not following link: \"");
                try printPath(sink, params.input_paths, &path);
                try sink.writeAll("\"\n");
                try sink.end();
            }
        },
        // ignore
        .block_device, .character_device, .named_pipe, .unix_domain_socket, .whiteout, .door, .event_port, .unknown => {},
    }

    return null;
}

fn searchFile(
    ring: *Ring,
    text_buf: []u8,
    line_buf: *ArrayList([]const u8),
    sink: *SinkBuf,
    params: *const Params,
    read_file: ReadFile,
    len: usize,
) !void {
    const path = &ring.paths[read_file.buf_idx];
    const opts = params.opts;
    const input_paths = params.input_paths;

    defer {
        ring.allocator.free(path.abs);

        const user_data = toUserData(.{ .CloseFile = read_file });
        if (ring.ring.close_direct(user_data, read_file.fd)) |_| {
            _ = ring.ring.submit() catch {};
        } else |_| {}
    }

    var chunk_buf = ChunkBuffer{
        .ring = ring,
        .read_file = read_file,
        .text_buf = text_buf,
        .pos = 0,
        .data_end = len,
        .is_last_chunk = len < TEXT_BUF_SIZE,
    };
    // TODO: start reading next chunk if not last chunk

    std.mem.copyForwards(u8, text_buf, ring.textBuf(read_file.buf_idx)[0..len]);
    var text: []const u8 = text_buf[0..len];
    var file_has_match = false;
    var line_num: u32 = 1;
    var last_matched_line_num: ?u32 = null;
    var last_printed_line_num: ?u32 = null;

    // detect binary files
    const null_byte = std.mem.indexOfScalar(u8, text, 0x00);
    if (null_byte) |_| {
        if (opts.debug) {
            try sink.writeAll("Not searching binary file: \"");
            try printPath(sink, input_paths, path);
            try sink.writeAll("\"\n");
            try sink.end();
        }
        return;
    }

    while (true) {
        var chunk_has_match = false;
        var line_iter = std.mem.splitScalar(u8, text[chunk_buf.pos..], '\n');
        var last_matched_line: ?[]const u8 = null;
        var printed_remainder = true;

        search: while (chunk_buf.pos < text.len) {
            var match: c.rure_match = undefined;
            const found = c.rure_find(params.regex, @ptrCast(text), text.len, chunk_buf.pos, &match);
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
                    if (match.end == line_end + 1 and text[line_end] == '\n') {
                        // don't include newlines in match text
                        match.end -= 1;
                    } else if (match.end > line_end) {
                        // Some regex pattern may match newlines, which shouldn't be supported by default.
                        // If the match spans multiple lines, check if the first line would be enough to match.
                        const search_start = match.start;
                        const search_end = @min(line_end + 1, text.len);
                        const single_line_found = c.rure_find(params.regex, @ptrCast(text), search_end, search_start, &match);

                        if (!single_line_found) {
                            if (last_matched_line) |lml| {
                                if (!printed_remainder) {
                                    _ = try printRemainder(sink, &chunk_buf, text, lml);
                                    last_printed_line_num = last_matched_line_num;
                                    printed_remainder = true;
                                }
                            }

                            chunk_buf.pos = search_end;
                            continue :search;
                        }

                        if (match.end == line_end + 1 and text[line_end] == '\n') {
                            // don't include newlines in match text
                            match.end -= 1;
                        }
                    }

                    current_line = line;
                    current_line_start = line_start;
                    break;
                }

                if (!printed_remainder) {
                    // remainder of last line
                    if (last_matched_line) |lml| {
                        chunk_buf.pos = try printRemainder(sink, &chunk_buf, text, lml);
                        last_printed_line_num = last_matched_line_num;
                        printed_remainder = true;
                    }
                }

                // after context lines
                if (last_matched_line_num) |lml_num| {
                    const is_after_context_line = line_num <= lml_num + opts.after_context;
                    const is_unprinted = last_printed_line_num orelse lml_num < line_num;
                    if (is_after_context_line and is_unprinted) {
                        try printLinePrefix(sink, opts, input_paths, path, line_num, '-');
                        try sink.print("{s}\n", .{line});
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
                    try sink.writeAll("\x1b[35m");
                }
                try printPath(sink, input_paths, path);
                if (opts.color) {
                    try sink.writeAll("\x1b[0m");
                }
                try sink.writeByte('\n');
            }

            const first_match_in_line = line_num != last_matched_line_num;
            if (first_match_in_line) {
                // non-contigous lines separator
                const lpl_num = last_printed_line_num orelse 0;
                const unprinted_before_lines = line_num - lpl_num - 1;
                if (opts.before_context > 0 or opts.after_context > 0) {
                    if (file_has_match and unprinted_before_lines > opts.before_context) {
                        try sink.writeAll("--\n");
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
                        try printLinePrefix(sink, opts, input_paths, path, cline_num, '-');
                        try sink.writeAll(cline);
                    }

                    line_buf.clearRetainingCapacity();
                }

                try printLinePrefix(sink, opts, input_paths, path, line_num, ':');

                chunk_has_match = true;
                file_has_match = true;
            }

            // preceding text
            const preceding_text_start = @max(current_line_start, chunk_buf.pos);
            const preceding_text = text[preceding_text_start..match.start];
            try sink.writeAll(preceding_text);

            // the match
            const match_text = text[match.start..match.end];
            if (opts.color) {
                try sink.writeAll("\x1b[0m\x1b[1m\x1b[31m");
            }
            try sink.writeAll(match_text);
            if (opts.color) {
                try sink.writeAll("\x1b[0m");
            }

            chunk_buf.pos = match.end;
            last_matched_line = current_line;
            last_matched_line_num = line_num;
            printed_remainder = false;
        }

        if (last_matched_line) |lml| {
            // remainder of last line
            if (!printed_remainder) {
                chunk_buf.pos = try printRemainder(sink, &chunk_buf, text, lml);
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
                try printLinePrefix(sink, opts, input_paths, path, line_num, '-');
                try sink.print("{s}\n", .{cline});

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
            try sink.writeByte('\n');
        }
    }

    try sink.end();
}

const ChunkBuffer = struct {
    ring: *Ring,
    read_file: ReadFile,
    text_buf: []u8,
    pos: usize,
    /// The end of data inside the chunk buffer, not the end of the text slice
    /// returned by refillChunkBuffer().
    data_end: usize,
    is_last_chunk: bool,
};

/// Moves the data after `new_start_pos` to the start of the internal buffer,
/// fills the remaining part of the buffer with data from `file` and updates
/// `chunk_buf.pos`, `chunk_buf.data_end` and `chunk_buf.is_last_chunk`.
/// Then returns a slice of text from the start of the internal buffer until
/// the last line ending. Newlines are included if they are present.
inline fn refillChunkBuffer(chunk_buf: *ChunkBuffer, new_start_pos: usize) ![]const u8 {
    // TODO: have a main text buffer that is twice the size of the iovecs used by iouring
    // always read a complete IO_URING_BUF_SIZE and copy over to the main text_buffer,
    // at the position we are at.
    // knowing what size to read allows reading further parts of the file while searching the current buffer...

    std.debug.assert(new_start_pos <= chunk_buf.pos);

    const num_reused_bytes = chunk_buf.data_end - new_start_pos;
    std.mem.copyForwards(u8, chunk_buf.text_buf, chunk_buf.text_buf[new_start_pos..chunk_buf.data_end]);
    chunk_buf.pos = chunk_buf.pos - new_start_pos;

    const ring = chunk_buf.ring;
    const read_file = chunk_buf.read_file;
    const user_data = toUserData(.{ .ReadFile = read_file });

    // IMPORTANT: has to stay valid until this operations com
    var buffer = ring.text_bufs[read_file.buf_idx];
    buffer.len -= num_reused_bytes;

    const file_offset: u64 = @bitCast(@as(i64, -1)); // just continue reading at the last position
    const sqe = try chunk_buf.ring.ring.read_fixed(user_data, read_file.buf_idx, &buffer, file_offset, read_file.buf_idx);
    sqe.flags |= std.os.linux.IOSQE_FIXED_FILE;
    _ = try ring.ring.submit();

    // block waiting for our read to come through
    const len: usize = while (true) {
        const cqe = try nextNewCqe(ring);
        std.debug.print("{}\n", .{cqe});
        switch (cqe.op) {
            .ReadFile => |f| {
                if (f.buf_idx == read_file.buf_idx) {
                    break @intCast(cqe.res);
                }
            },
            else => {
                ring.queue[ring.queue_end % IO_URING_BUF_SIZE] = cqe;
                ring.queue_end += 1;
            },
        }
    };

    chunk_buf.data_end = num_reused_bytes + len;
    chunk_buf.is_last_chunk = chunk_buf.data_end < chunk_buf.text_buf.len;

    var text_end = chunk_buf.data_end;
    if (!chunk_buf.is_last_chunk) {
        const last_line_end = indexOfScalarPosRev(u8, chunk_buf.text_buf, chunk_buf.data_end, '\n');
        if (last_line_end) |end| {
            text_end = end;
        }
    }
    return chunk_buf.text_buf[0..text_end];
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

inline fn printLinePrefix(sink: *SinkBuf, opts: *const UserOptions, input_paths: []const []const u8, path: *const DisplayPath, line_num: u32, sep: u8) !void {
    if (!opts.heading) {
        // path
        if (opts.color) {
            try sink.writeAll("\x1b[35m");
        }
        try printPath(sink, input_paths, path);
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

inline fn printPath(sink: *SinkBuf, input_paths: []const []const u8, path: *const DisplayPath) !void {
    const sub_path = path.abs[path.sub_path_offset..];
    if (path.display_prefix) |pi| {
        const p = input_paths[pi];
        try sink.writeAll(p);
        if (sub_path.len > 0 and p.len > 0 and p[p.len - 1] != std.fs.path.sep) {
            try sink.writeByte(std.fs.path.sep);
        }
    }
    if (sub_path.len > 0) {
        try sink.writeAll(sub_path[1..]);
    }
}

/// Prints the remainder of `lml`. The remainder is found by comparing the `lml.ptr` with `text.ptr`.
/// Returns the end of the line.
inline fn printRemainder(sink: *SinkBuf, chunk_buf: *ChunkBuffer, text: []const u8, lml: []const u8) !usize {
    const lml_start = textIndex(text, lml);
    const lml_end = lml_start + lml.len;

    std.debug.assert(chunk_buf.pos <= lml_end);

    const remainder = text[chunk_buf.pos..lml_end];
    try sink.print("{s}\n", .{remainder});

    return @min(lml_end + 1, text.len);
}

inline fn allocSlice(comptime T: type, allocator: Allocator, slice: []const T) ![]T {
    const buf = try allocator.alloc(T, slice.len);
    @memcpy(buf, slice);
    return buf;
}

/// Check if the symlink contains a loop. `abs_search_path` is where the
/// symlink lives, and `abs_link_path` is where it points to.
fn symlinkLoops(abs_search_path: []const u8, abs_link_path: []const u8) bool {
    return std.mem.startsWith(u8, abs_search_path, abs_link_path);
}

test "symlink loop detection" {
    try std.testing.expect(symlinkLoops("/a/b/c/d/e/f", "/a"));
    try std.testing.expect(symlinkLoops("/a/b/c/d/e/f", "/a/b/c/d"));
    try std.testing.expect(!symlinkLoops("/a/b/c/d/e/f", "/a/b/o"));
    try std.testing.expect(!symlinkLoops("/a/b/c/d/e/f", "/a/b/c/d/o"));
    try std.testing.expect(!symlinkLoops("/a/b/c/d/e/f", "/o"));
}
