const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const File = std.fs.File;

pub const MessageType = enum {
    Some,
    Stop,
};

fn AtomicMessage(comptime T: type) type {
    return union(MessageType) {
        Some: T,
        Stop: void,
    };
}

/// Thread safe priority stack with stop signal.
pub fn AtomicStack(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex,
        condition: std.Thread.Condition,
        alive_workers: u32,
        buf: *ArrayList(Entry),

        const Self = @This();
        pub const Message = AtomicMessage(Entry);
        pub const Entry = struct {
            priority: u16,
            data: T,
        };

        /// Initialize the stack, there is no `deinit`.
        ///
        /// IMPORTANT: `num_workers` has to be the exact amount of workers using
        /// the stack, otherwise even if all are blocking no stop signal is sent.
        pub fn init(buf: *ArrayList(Entry), num_workers: u32) Self {
            std.debug.assert(num_workers > 0);

            return Self{
                .mutex = std.Thread.Mutex{},
                .condition = std.Thread.Condition{},
                .alive_workers = num_workers,
                .buf = buf,
            };
        }

        /// Push an entry onto the stack, a higher `entry.priority`
        pub fn push(self: *Self, entry: Entry) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            var i = self.buf.items.len;
            while (i > 0) {
                i -= 1;
                const e = self.buf.items[i];
                if (e.priority < entry.priority) {
                    i += 1;
                    break;
                }
            }
            try self.buf.insert(i, entry);
            self.condition.signal();
        }

        /// Get the topmost item or a stop signal.
        ///
        /// If the stack is empty, this will block until a message is available.
        /// Once all workers are waiting (dead), the stop signal is sent.
        pub fn pop(self: *Self) Message {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.buf.items.len == 0) {
                self.alive_workers -= 1;
                if (self.alive_workers == 0) {
                    self.condition.broadcast();
                    return .Stop;
                }

                self.condition.wait(&self.mutex);

                self.alive_workers += 1;
            }

            const val = self.buf.pop();

            return Message{ .Some = val };
        }
    };
}

/// Synchronizes output from several threads.
///
/// This is the thread safe writer that is shared by `SinkBuf`s from other threads.
pub const Sink = struct {
    mutex: std.Thread.Mutex,
    writer: File.Writer,

    const Self = @This();

    /// Initialize the queue, there is no `deinit`.
    pub fn init(writer: File.Writer) Self {
        return Self{
            .mutex = std.Thread.Mutex{},
            .writer = writer,
        };
    }

    /// Start an exclusive transaction. This must be followed by calling
    /// `endExclusive()` to unblock other threads from using the writer.
    fn startExclusive(self: *Self) *File.Writer {
        self.mutex.lock();
        return &self.writer;
    }

    /// End the exclusive transaction, requires a pointer to the exclusive writer,
    /// to be handed in so it can be cleared.
    fn endExclusive(self: *Self, writer: *?*File.Writer) void {
        writer.* = null;
        self.mutex.unlock();
    }
};

/// A thread local buffer that writes to a `Sink`.
///
/// Buffer output as long as possible and then write it to the `Sink`
/// atomically. If the buffer overflows, this will start an exclusive
/// transaction that blocks other threads `SinkBuf`s from writing.
///
/// IMPORTANT: `end` has to be called manually, otherwise all other writers will
/// be blocked, once an exclusive transaction has started.
pub const SinkBuf = struct {
    sink: *Sink,
    buf: []u8,
    pos: usize,
    exclusive_writer: ?*File.Writer,

    const Self = @This();

    const Writer = std.io.GenericWriter(
        *Self,
        std.posix.WriteError,
        Self.writeFn,
    );

    inline fn writer(self: *Self) Writer {
        return Writer{ .context = self };
    }

    /// Initialize the queue, there is no `deinit`, and the `buf` has to be
    /// cleaned up by the caller.
    pub fn init(sink: *Sink, buf: []u8) Self {
        std.debug.assert(buf.len > 0);

        return Self{
            .sink = sink,
            .buf = buf,
            .pos = 0,
            .exclusive_writer = null,
        };
    }

    // only used for writer
    fn writeFn(context: *Self, bytes: []const u8) std.posix.WriteError!usize {
        try context.writeAll(bytes);
        return bytes.len;
    }

    /// Write into the thread local buffer, if it overflows an exclusive
    /// transaction is started.
    pub fn writeByte(self: *Self, byte: u8) !void {
        if (self.pos >= self.buf.len) {
            try self.flush();
        }

        if (self.pos < self.buf.len) {
            self.buf[self.pos] = byte;
            self.pos += 1;
        }
    }

    /// Write into the thread local buffer, if it overflows an exclusive
    /// transaction is started.
    pub fn writeAll(self: *Self, slice: []const u8) !void {
        if (self.pos + slice.len >= self.buf.len) {
            try self.flush();
        }
        if (slice.len > self.buf.len) {
            // no need to buffer slice is larger than our buffer anyway.
            const w = self.ensureExclusive();
            try w.writeAll(slice);
        } else {
            @memcpy(self.buf[self.pos .. self.pos + slice.len], slice);
            self.pos += slice.len;
        }
    }

    /// Write into the thread local buffer, if it overflows an exclusive
    /// transaction is started.
    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        try std.fmt.format(self.writer(), fmt, args);
    }

    /// Force exclusive transaction to start and write content.
    pub fn flush(self: *Self) !void {
        const w = self.ensureExclusive();
        try self.flushInternal(w);
    }

    /// Write remaining content, if any and end exclusive transaction.
    pub fn end(self: *Self) !void {
        if (self.exclusive_writer == null and self.pos == 0) {
            return;
        }

        const w = self.ensureExclusive();
        try self.flushInternal(w);
        self.sink.endExclusive(&self.exclusive_writer);
    }

    inline fn ensureExclusive(self: *Self) *File.Writer {
        if (self.exclusive_writer) |w| {
            return w;
        } else {
            const w = self.sink.startExclusive();
            self.exclusive_writer = w;
            return w;
        }
    }

    inline fn flushInternal(self: *Self, exclusive_writer: *File.Writer) !void {
        try exclusive_writer.writeAll(self.buf[0..self.pos]);
        self.pos = 0;
    }
};
