const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Futex = std.Thread.Futex;
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

/// Thread safe ringbuffer queue with stop signal.
pub fn AtomicQueue(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex,
        state: std.atomic.Atomic(State),
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
                .state = .{ .value = .Empty },
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
            self.state.store(new_state, std.atomic.Ordering.SeqCst);
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
            self.state.store(new_state, std.atomic.Ordering.SeqCst);
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
            self.state.store(new_state, std.atomic.Ordering.SeqCst);
            Futex.wake(@ptrCast(&self.state), 1);

            return Message{ .Some = data };
        }
    };
}

/// Thread safe stack, with stop signal.
pub fn AtomicStack(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex,
        alive_workers: u32,
        state: std.atomic.Atomic(u32),
        buf: ArrayList(Entry),

        const Self = @This();
        const Message = AtomicMessage(Entry);
        const Entry = struct {
            depth: u16,
            data: T,
        };
        const State = enum(u32) {
            Empty,
            NoneEmpty,
            Stop,
        };

        /// Initialize the queue, `deinit` has to be called.
        pub fn init(buf: ArrayList(Entry), num_workers: u32) Self {
            std.debug.assert(num_workers > 0);

            return Self{
                .mutex = std.Thread.Mutex{},
                .state = std.atomic.Atomic(u32).init(num_workers),
                .buf = buf,
            };
        }

        pub fn push(self: *Self, entry: Entry) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // depth first iteration, so avoid putting a higher directory on top of the stack.
            const idx = for (self.buf.items, 0..) |e, i| {
                if (e.depth > entry.depth) {
                    break i;
                }
            } else self.buf.items.len;
            self.buf.insert(idx, entry);
            self.state.store(&self.state, std.atomic.Ordering.SeqCst);
            Futex.wake(&self.state, 1);
        }

        pub fn pop(self: *Self) Message {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.buf.items.len == 0) {
                self.alive_workers -= 1;
                if (self.alive_workers == 0) {
                    self.state.store(@intFromEnum(.Stop), std.atomic.Ordering.SeqCst);
                    Futex.wake(&self.state, std.math.maxInt(u32));
                    return .Stop;
                }

                self.mutex.unlock();
                Futex.wait(&self.state, @intFromEnum(.Empty));
                self.mutex.lock();

                self.alive_workers += 1;
            }

            const val = self.buf.pop();

            if (self.buf.items.len == 0) {
                self.state.store(@intFromEnum(.Empty), std.atomic.Ordering.SeqCst);
            }

            return Message{ .Some = val };
        }
    };
}

/// Synchronizes output to the underlying writer, so files don't mix.
///
/// TODO: buffer per thread, so this only blocks when flushing the buffer.
const Sink = struct {
    mutex: std.Thread.Mutex,
    writer: File.Writer,

    const Self = @This();

    fn init(writer: File.Writer) Self {
        return Self{
            .mutex = std.Thread.Mutex{},
            .writer = writer,
        };
    }

    fn writeByte(self: *Self, byte: u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.writer.writeByte(byte);
    }

    fn writeAll(self: *Self, slice: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.writer.writeAll(slice);
    }

    fn print(self: *Self, comptime format: []const u8, arg: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.writer.print(format, arg);
    }

    /// Signal that the current writer is done.
    fn flush(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
    }
};
