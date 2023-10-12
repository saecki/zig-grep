const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const File = std.fs.File;
const IterableDir = std.fs.IterableDir;

const UserOptions = struct {
    before_context: usize = 0,
    after_context: usize = 0,
    colored: bool = false,
    heading: bool = true,
    ignore_case: bool = false,
};

const StackEntry = struct {
    prev_dirname_len: usize,
    iter: IterableDir.Iterator,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // read arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // discard executable
    _ = args.next();

    var input_pattern: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;

    var follow_links = false;
    var hidden = false;
    var user_options = UserOptions{};

    // parse command line arguments
    while (args.next()) |arg| {
        if (input_pattern == null) {
            input_pattern = arg;
        } else if (input_path == null) {
            input_path = arg;
        } else {
            try stdout.print("Too many arguments", .{});
            std.process.exit(1);
        }
    }

    const pattern = input_pattern orelse {
        try stdout.print("Missing required positional argument [PATTERN]t", .{});
        std.process.exit(1);
    };

    // canonicalize path
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_path = try std.fs.realpath(input_path orelse ".", &path_buf);

    try stdout.print("Search pattern {?s}\n", .{pattern});
    try stdout.print("Search path {?s}\n", .{abs_path});

    // open path to search
    const open_options = .{ .no_follow = !follow_links };
    const dir = try std.fs.openIterableDirAbsolute(abs_path, open_options);

    // the currently searched path name
    var dirname_len: usize = 0;
    var name_buffer = std.ArrayList(u8).init(allocator);
    defer name_buffer.deinit();
    if (input_path) |p| {
        try name_buffer.appendSlice(p);
        dirname_len += p.len;
    }

    // the stack of searched directories
    var dir_stack = std.ArrayList(StackEntry).init(allocator);
    defer dir_stack.deinit();

    // reuse text buffers
    var text_buffer: []u8 = &[_]u8{};
    defer allocator.free(text_buffer);
    var line_buffer: [][]u8 = try allocator.alloc([]u8, user_options.before_context);
    defer allocator.free(line_buffer);

    // push first dir entry
    try dir_stack.append(StackEntry{
        .prev_dirname_len = 0,
        .iter = dir.iterate(),
    });

    // recursively search the path
    while (dir_stack.items.len != 0) {
        name_buffer.shrinkRetainingCapacity(dirname_len);

        var current = &dir_stack.items[dir_stack.items.len - 1];
        var entry = try current.iter.next() orelse {
            dirname_len = current.prev_dirname_len;
            current.iter.dir.close();
            _ = dir_stack.pop();
            continue;
        };

        var additional_len: usize = 0;
        if (dirname_len != 0 and name_buffer.items[dirname_len - 1] != '/') {
            try name_buffer.append(std.fs.path.sep);
            additional_len += 1;
        }
        try name_buffer.appendSlice(entry.name);
        additional_len += entry.name.len;

        // skip hidden files
        if (!hidden and entry.name[0] == '.') {
            continue;
        }

        switch (entry.kind) {
            .file => {
                try stdout.print("File:    {s}\n", .{name_buffer.items});
                const open_flags = .{ .mode = .read_only };
                var file = try current.iter.dir.openFile(entry.name, open_flags);
                try searchFile(
                    stdout,
                    allocator,
                    &text_buffer,
                    line_buffer,
                    name_buffer.items,
                    file,
                    pattern,
                    &user_options,
                );
            },
            .directory => {
                try stdout.print("Dir:     {s}\n", .{name_buffer.items});

                const new_dir = try current.iter.dir.openIterableDir(entry.name, open_options);
                const stack_entry = StackEntry{
                    .prev_dirname_len = dirname_len,
                    .iter = new_dir.iterate(),
                };
                try dir_stack.append(stack_entry);

                dirname_len += additional_len;
            },
            .sym_link => {
                try stdout.print("Symlink: {s}\n", .{name_buffer.items});
                if (follow_links) {
                    // TODO: follow symlink
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

fn searchFile(
    stdout: File.Writer,
    allocator: Allocator,
    text_buffer: *[]u8,
    line_buffer: [][]u8,
    path: []const u8,
    file: File,
    pattern: []const u8,
    user_options: *const UserOptions,
) !void {
    _ = pattern;
    const stat = try file.stat();
    if (text_buffer.len < stat.size) {
        text_buffer.* = try allocator.realloc(text_buffer.*, stat.size);
    }

    const len = try file.readAll(text_buffer.*);
    const text = text_buffer.*[0..len];

    // TODO: iterate over lines filling line buffer, while searching for pattern

    if (user_options.heading) {
        if (user_options.colored) {
            try stdout.print("\x1b[31m", .{});
        }
        try stdout.print("{s}", .{path});
        if (user_options.colored) {
            try stdout.print("\x1b[0m", .{});
        }
        try stdout.print("\n", .{});
    }
    try stdout.print("{s}\n", .{text});
    _ = line_buffer;
}
