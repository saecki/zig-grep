const std = @import("std");
const Dir = std.fs.Dir;
const IterableDir = std.fs.IterableDir;

const StackEntry = struct {
    prev_dirname_len: usize,
    iter: IterableDir.Iterator,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // discard executable
    _ = args.next();

    var pattern: ?[]const u8 = null;
    var path: ?[]const u8 = null;

    var follow_links = false;

    // parse command line arguments
    while (args.next()) |arg| {
        if (pattern == null) {
            pattern = arg;
        } else if (path == null) {
            path = arg;
        } else {
            std.debug.print("Too many arguments", .{});
            std.process.exit(1);
        }
    }

    if (pattern == null) {
        std.debug.print("Missing required positional argument [PATTERN]t", .{});
        std.process.exit(1);
    }

    // canonicalize path
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_path = try std.fs.realpath(path orelse ".", &path_buf);

    std.debug.print("Search pattern {?s}\n", .{pattern});
    std.debug.print("Search path {?s}\n", .{abs_path});

    // open path to search
    const open_options = Dir.OpenDirOptions{ .no_follow = !follow_links };
    const dir = try std.fs.openIterableDirAbsolute(abs_path, open_options);

    // the currently searched path name
    var dirname_len: usize = 0;
    var name_buffer = std.ArrayList(u8).init(allocator);
    defer name_buffer.deinit();
    var dir_stack = std.ArrayList(StackEntry).init(allocator);
    defer dir_stack.deinit();
    if (path) |p| {
        try name_buffer.appendSlice(p);
        dirname_len += p.len;
    }

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
        if (dirname_len != 0) {
            try name_buffer.append(std.fs.path.sep);
            additional_len += 1;
        }
        try name_buffer.appendSlice(entry.name);
        additional_len += entry.name.len;

        switch (entry.kind) {
            .file => {
                std.debug.print("File:    {s}\n", .{name_buffer.items});
            },
            .directory => {
                std.debug.print("Dir:     {s}\n", .{name_buffer.items});

                const new_dir = try current.iter.dir.openIterableDir(entry.name, open_options);
                const stack_entry = StackEntry{
                    .prev_dirname_len = dirname_len,
                    .iter = new_dir.iterate(),
                };
                try dir_stack.append(stack_entry);

                dirname_len += additional_len;
            },
            .sym_link => {
                std.debug.print("Symlink: {s}\n", .{name_buffer.items});
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
