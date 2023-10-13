const c = @cImport({
    @cInclude("rure.h");
});

const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;
const File = std.fs.File;
const IterableDir = std.fs.IterableDir;

const UserOptions = struct {
    before_context: usize = 0,
    after_context: usize = 0,
    colored: bool = true,
    heading: bool = true,
    ignore_case: bool = false,

    print_newline: bool = false,
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
        // TODO: parse users options
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
        try stdout.print("Missing required positional argument [PATTERN]\n", .{});
        std.process.exit(1);
    };

    // compile regex
    const regex_flags: u32 = if (user_options.ignore_case) @bitCast(c.RURE_FLAG_CASEI) else 0;
    var regex_error: ?*c.rure_error = null;
    const maybe_regex = c.rure_compile(@ptrCast(pattern), pattern.len, regex_flags, null, regex_error);
    const regex = maybe_regex orelse {
        defer c.rure_error_free(regex_error);
        const error_message = c.rure_error_message(regex_error);
        try stdout.print("Error compiling pattern \"{s}\" regex:{s}\n", .{ pattern, error_message });
        std.process.exit(1);
    };
    defer c.rure_free(regex);

    // canonicalize path
    var path_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs_path = try std.fs.realpath(input_path orelse ".", &path_buf);

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
                const open_flags = .{ .mode = .read_only };
                var file = try current.iter.dir.openFile(entry.name, open_flags);
                try searchFile(
                    stdout,
                    allocator,
                    &text_buffer,
                    line_buffer,
                    name_buffer.items,
                    file,
                    regex,
                    &user_options,
                );
            },
            .directory => {
                const new_dir = try current.iter.dir.openIterableDir(entry.name, open_options);
                const stack_entry = StackEntry{
                    .prev_dirname_len = dirname_len,
                    .iter = new_dir.iterate(),
                };
                try dir_stack.append(stack_entry);

                dirname_len += additional_len;
            },
            .sym_link => {
                try stdout.print("Symlink: {s}\nTODO: support symlinks", .{name_buffer.items});
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
    regex: *c.rure,
    user_options: *const UserOptions,
) !void {
    const stat = try file.stat();
    if (text_buffer.len < stat.size) {
        text_buffer.* = try allocator.realloc(text_buffer.*, stat.size);
    }

    const len = try file.readAll(text_buffer.*);
    const text = text_buffer.*[0..len];

    // TODO: binary file checks
    // TODO: iterate over lines filling line buffer, while searching for pattern

    var file_has_match = false;
    var line_iter = std.mem.splitScalar(u8, text, '\n');
    var i: u32 = 0;
    while (line_iter.next()) |line| {
        var line_has_match = false;
        var current_pos: usize = 0;
        var match: c.rure_match = undefined;
        var match_iter = c.rure_iter_new(regex);
        defer c.rure_iter_free(match_iter);

        while (c.rure_iter_next(match_iter, @ptrCast(line), line.len, &match)) {
            if (!file_has_match and user_options.heading) {
                if (user_options.colored) {
                    try stdout.print("\x1b[34m", .{});
                }
                try stdout.print("{s}", .{path});
                if (user_options.colored) {
                    try stdout.print("\x1b[0m", .{});
                }
                try stdout.print("\n", .{});

                file_has_match = true;
            }

            if (current_pos == 0) {
                // path
                if (!user_options.heading) {
                    if (user_options.colored) {
                        try stdout.print("\x1b[34m", .{});
                    }
                    try stdout.print("{s}", .{path});
                    if (user_options.colored) {
                        try stdout.print("\x1b[0m", .{});
                    }
                    try stdout.print(":", .{});
                }

                // line number
                const line_num = i + 1;
                if (user_options.colored) {
                    try stdout.print("\x1b[32m", .{});
                }
                try stdout.print("{}", .{line_num});
                if (user_options.colored) {
                    try stdout.print("\x1b[0m", .{});
                }
                try stdout.print(":", .{});
            }

            if (current_pos != match.start) {
                const prev_text = line[current_pos..match.start];
                try stdout.print("{s}", .{prev_text});
            }

            const match_text = line[match.start..match.end];
            if (user_options.colored) {
                try stdout.print("\x1b[91m", .{});
            }
            try stdout.print("{s}", .{match_text});
            if (user_options.colored) {
                try stdout.print("\x1b[0m", .{});
            }

            line_has_match = true;
            current_pos = match.end;
        }

        if (line_has_match) {
            if (current_pos != line.len) {
                const remaining_text = line[current_pos..line.len];
                try stdout.print("{s}\n", .{remaining_text});
            } else {
                try stdout.print("\n", .{});
            }
        }

        i += 1;
    }

    if (file_has_match and user_options.print_newline) {
        try stdout.print("\n", .{});
    }

    _ = line_buffer;
}
