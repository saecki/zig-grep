const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Futex = std.Thread.Futex;
const File = std.fs.File;

const AtomicOrder = std.builtin.AtomicOrder;

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

/// Thread safe ringbuffer queue with stop signal.
pub fn AtomicQueue(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex,
        state: std.atomic.Value(State),
        buf: []T,
        pos: usize,
        len: usize,
        stop_signal: bool,

        const Self = @This();
        const Message = AtomicMessage(T);
        const State = enum(u32) {
            Empty,
            NonEmpty,
            Full,
        };

        /// Initialize the queue, there is no `deinit`, and the `buf` has to be
        /// cleaned up by the caller.
        pub fn init(buf: []T) Self {
            return Self{
                .mutex = std.Thread.Mutex{},
                .state = std.atomic.Value(State).init(.Empty),
                .buf = buf,
                .pos = 0,
                .len = 0,
                .stop_signal = false,
            };
        }

        /// Append data to the queue.
        /// Calling `append` after `stop` has been called is valid but pointless.
        /// It will just be ignored.
        ///
        /// If the internal ringbuffer is full, this will block until space is available.
        pub fn append(self: *Self, data: T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.stop_signal) {
                return;
            }

            while (self.len >= self.buf.len) {
                self.mutex.unlock();
                Futex.wait(@ptrCast(&self.state), @intFromEnum(State.Full));
                self.mutex.lock();

                if (self.stop_signal) {
                    return;
                }
            }

            const next_pos = (self.pos + self.len) % self.buf.len;
            self.buf[next_pos] = data;
            self.len += 1;

            const new_state: State = if (self.len == self.buf.len) .Full else .NonEmpty;
            self.state.store(new_state, AtomicOrder.SeqCst);
            Futex.wake(@ptrCast(&self.state), 1);
        }

        /// Sends the stop signal, which will make calling `get` always yield
        /// Message.Stop, once all previous data has been consumed.
        ///
        /// This won't block, even if the internal ringbuffer is full.
        pub fn stop(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.stop_signal) {
                return;
            }

            self.stop_signal = true;
            const new_state: State = if (self.len == self.buf.len) .Full else .NonEmpty;
            self.state.store(new_state, AtomicOrder.SeqCst);
            const max_waiters: u32 = if (self.len == 0) std.math.maxInt(u32) else 1;
            Futex.wake(@ptrCast(&self.state), max_waiters);
        }

        /// Get queued up data, or a stop message
        ///
        /// If the internal ringbuffer is empty, this will block until a message
        /// is available.
        pub fn get(self: *Self) Message {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.len == 0) {
                if (self.stop_signal) {
                    return .Stop;
                }

                self.mutex.unlock();
                Futex.wait(@ptrCast(&self.state), @intFromEnum(State.Empty));
                self.mutex.lock();
            }

            const data = self.buf[self.pos];

            self.pos = (self.pos + 1) % self.buf.len;
            self.len -= 1;

            const new_state: State = if (self.len == 0 and !self.stop_signal) .Empty else .NonEmpty;
            self.state.store(new_state, AtomicOrder.SeqCst);
            const max_waiters: u32 = if (self.len == 0 and self.stop_signal) std.math.maxInt(u32) else 1;
            Futex.wake(@ptrCast(&self.state), max_waiters);

            return Message{ .Some = data };
        }
    };
}

/// Thread safe stack, with stop signal.
pub fn AtomicStack(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex,
        state: std.atomic.Value(u32),
        alive_workers: u32,
        buf: *ArrayList(Entry),

        const Self = @This();
        pub const Message = AtomicMessage(Entry);
        pub const Entry = struct {
            depth: u16,
            data: T,
        };
        pub const State = enum(u32) {
            Empty,
            NonEmpty,
            Stop,
        };

        /// Initialize the queue, there is no `deinit`.
        pub fn init(buf: *ArrayList(Entry), num_workers: u32) Self {
            std.debug.assert(num_workers > 0);

            const state: State = if (buf.items.len == 0) .Empty else .NonEmpty;
            return Self{
                .mutex = std.Thread.Mutex{},
                .state = std.atomic.Value(u32).init(@intFromEnum(state)),
                .alive_workers = num_workers,
                .buf = buf,
            };
        }

        pub fn push(self: *Self, entry: Entry) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // depth first iteration, so avoid putting a higher directory on top of the stack.
            var i = self.buf.items.len;
            while (i > 0) {
                i -= 1;
                const e = self.buf.items[i];
                if (e.depth < entry.depth) {
                    i += 1;
                    break;
                }
            }
            try self.buf.insert(i, entry);
            self.state.store(@intFromEnum(State.NonEmpty), AtomicOrder.SeqCst);
            Futex.wake(&self.state, 1);
        }

        pub fn pop(self: *Self) Message {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.buf.items.len == 0) {
                self.alive_workers -= 1;
                if (self.alive_workers == 0) {
                    self.state.store(@intFromEnum(State.Stop), AtomicOrder.SeqCst);
                    Futex.wake(&self.state, std.math.maxInt(u32));
                    return .Stop;
                }

                self.mutex.unlock();
                Futex.wait(&self.state, @intFromEnum(State.Empty));
                self.mutex.lock();

                self.alive_workers += 1;
            }

            const val = self.buf.pop();

            if (self.buf.items.len == 0) {
                self.state.store(@intFromEnum(State.Empty), AtomicOrder.SeqCst);
            }

            return Message{ .Some = val };
        }
    };
}

/// Synchronizes output from several threads.
///
/// This is the thread safe shared writer that all `SinkBuf`s from other threads
pub const Sink = struct {
    mutex: std.Thread.Mutex,
    writer: File.Writer,

    const Self = @This();

    pub fn init(writer: File.Writer) Self {
        return Self{
            .mutex = std.Thread.Mutex{},
            .writer = writer,
        };
    }

    /// Start an exclusive transaction. This must be followed by calling
    /// `unlock()` to unblock other threads from using the writer.
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

    const Writer = struct {
        sink_buf: *SinkBuf,

        pub const Error = std.os.WriteError;

        pub fn writeByte(self: Writer, byte: u8) !void {
            try self.sink_buf.writeByte(byte);
        }

        pub fn writeAll(self: Writer, slice: []const u8) !void {
            try self.sink_buf.writeAll(slice);
        }

        pub fn writeByteNTimes(self: Writer, byte: u8, n: usize) !void {
            var bytes: [256]u8 = undefined;
            @memset(bytes[0..], byte);

            var remaining: usize = n;
            while (remaining > 0) {
                const to_write = @min(remaining, bytes.len);
                try self.sink_buf.writeAll(bytes[0..to_write]);
                remaining -= to_write;
            }
        }
    };

    inline fn writer(self: *Self) Writer {
        return Writer{ .sink_buf = self };
    }

    pub fn init(sink: *Sink, buf: []u8) Self {
        std.debug.assert(buf.len > 0);

        return Self{
            .sink = sink,
            .buf = buf,
            .pos = 0,
            .exclusive_writer = null,
        };
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
            var w = self.ensureExclusive();
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
