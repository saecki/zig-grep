#import "template.typ": *
#import "@preview/codelst:1.0.0": sourcecode

#show: project.with(
  title: "Seminar Programmiersprachen im Verlgeich - Zig",
  author: "Tobias Schmitz",
)

#outline()
#pagebreak()

= Introduction
The objective of this seminar was getting to know a new programming language by writing a simple grep like program.

= Language
== About
Zig is a general-purpose compiled systems programming language.
Andrew Kelley
2015/2016
Zig software foundation
    only no strings attached donations
It is often mentioned as a successor to C.

== Toolchain
Installation was as simple as downloading the release tar archive, extracting the toolchain, and symlinking the binary onto a `$PATH`.

The compiler is a single executable called `zig`, it includes a build system which can be configured in a `build.zig` file. The configuration is written in zig itself and thus avoids a separate language just for the build system. The toolchain itself is also a C/C++ compiler which allows zig code to directly interoperate with existing C/C++ code from zig.

To start a new project inside an existing directory running `zig init-exe` will generate the main source file `src/main.zig` and the build configuration `build.zig`. The program can then be built and executed by running `zig build run`.

The zig community also provides a language server called `zls`, which worked out of the box in neovim. There were some issues with type inference, and completion of member functions of generic types.

== Integers
Zig has concrete integer types with a predetermined size regardless of platform.
Common ones are:
- unsigned: `u8`, `u16`, `u32`, `u64`
- signed: `i8`, `i16`, `i32`, `i64`.
But it also allows defining arbitrary sized integers like `i27`, or `u3`, up to a bit-width of `65535`.

Zig arrays have a size known at compile time and are stack allocated, unless specified otherwise:
#sourcecode[```zig
    const explicit_length = [5]u32{ 0, 1, 2, 3, 4 };
    const inferred_length = [_]u32{ 5, 6, 7, 8, 9 };
```]

== Arrays and slices
Arrays can be sliced using the index operator with an end-exclusive range, returning a slice to the referenced array. By default the slice is a fat pointer which includes a pointer that points to the memory address of the slice inside the array, and the length of the slice.
#sourcecode[```zig
    const array = [_]u32{ 0, 1, 2, 3, 4 };
    const slice = array[1..3];
    std.debug.print("{d}\n", .{slice.*});
```]
The output prints:
#sourcecode[```
{ 1, 2 }
```]
For better interoperability with `C` zig also allows sentinel terminated pointers or slices. Most commonly this is used for null-terminated strings:
#sourcecode[```zig
    const string: *const [32:0]u8 = "this is a null terminated string";
    const fat_pointer_string_slice: []const u8 = string[10..];
    const null_terminated_string_slice: [:0]const u8 = string[10..];
    const null_terminated_string_ptr: [*:0]const u8 = string[10..];

    std.debug.print("size: {}, '{s}'\n", .{@sizeOf([]const u8), fat_pointer_string_slice});
    std.debug.print("size: {}, '{s}'\n", .{@sizeOf([:0]const u8), null_terminated_string_slice});
    std.debug.print("size: {}, '{s}'\n", .{@sizeOf([*:0]const u8), null_terminated_string_ptr});

```]
All three slice/pointer types reference the same data, but in a different way. Variant 1 uses the fat pointer approach described above. Variant 2 also uses the same approach but also upholds the constraint that the end of the slice is terminated by a null-byte sentinel. Variant 3 only stores a memory address and relies upon the null-byte sentinel to compute the length of the referenced data when needed.
As a result the first and the second slice type have a size of 16 bytes, 8 bytes for the pointer and 8 additional bytes for the length. The sentinel terminated pointer only has a size of 8 bytes, since it doesn't store an additional length field.a
A limitation of sentinel terminated slices or pointers is that they cannot reference arbitrary parts of an array. Trying to do so fails with the following message:
#sourcecode[```
src/main.zig:10:62: error: expected type '[:0]const u8', found '*const [13]u8'
    const null_terminated_string_slice: [:0]const u8 = string[10..23];
                                                       ~~~~~~^~~~~~~~
src/main.zig:10:62: note: destination pointer requires '0' sentinel
```]

== Type inference
The type of zig variables is inferred only using directly assigned values. A type can optionally be specified, and is required in some cases. For example when an integer literal is assigned to a mutable variable, it's exact type must be specified.
When the type of a struct is known, for example when passing it to a function, it's name can be omitted and an anonymous literal can be used:
#sourcecode[```zig
    struct Foo {
        a: i32,
        b: bool = false,
    }
    fn doSomething(value: Foo) {
        ...
    }

    doSomething(.{ .a = 21 });
```]
The same is also true for enums and tagged unions. When the type is known, the name of the enum can be omitted and only the variant needs to written out:
#sourcecode[```zig
    enum Bar {
        One,
        Two,
        Three,
    }
    const BAR_THREE: Bar = .Three;
```]

== Control flow primitives
- exhaustive switch statements
    - useful for enums

== Error handling
- errors as values
    - error union explicit or implict
    - try: return on error
    - catch: handle error
In zig there are no exceptions and errors are treated as values. If a function can fail, it returns an error union, the error set of that union can either be inferred or explicitly defined.\
Like rust zig has a try operator that either returns the error from the current function or unwraps the value.
#sourcecode[```zig
    fn printSomething() !void {
        const stdout = std.io.getStdOut();
        try stdout.writeAll("something\n");
    }

    const NullError = error{IsNull};

    fn checkNull(num: usize) NullError!void {
        if (num == 0) {
            return error.IsNull;
        }
    }
```]

== Defering
There are no destructors in zig, so unlike for example C++ the RAII model can't be used to make objects manage their resources automatically. Instead a common pattern to deal with closable resources is to define an `init` and a `deinit` function, which have to be called manually.

When dealing with multiple resources that depend on each other, they have to be called in reverse initialization order to be properly cleaned up.
To make this more ergonomic zig provides `defer` or `errdefer` keywords, which allow defering cleanup code.
`defer` runs code when the value goes out of scope:
#sourcecode[```zig
    fn readString() ![]const u8 {
        var file = try std.fs.cwd().openFile("foo.txt", .{});
        defer file.close();
        ...
    }
```]

`errdefer` runs code only when an error is returned from the scope, this can be useful when dealing with multiple steps that can fail, to clean up intermediate resources.

== Memory management
Zig doesn't include a garbage collector and uses a very explicit manual memory management strategy.\
Allocators are manually instantiated and passed to data structures or function which might allocate. The standard library includes a range of allocators fit for different use cases, ranging from general purpose, and arena, to fixed buffer allocators.\
Memory allocation may fail, and out of memory errors must be handled. Memory deallocation must always succeed.
Like other resources, data structures that allocate provide a `deinit` procedure that can be `defer`ed to deallocate the used memory.\
In debug mode zig keeps track of allocations and detects memory leaks.

== Comptime
Zig provides a powerful compile time evaluation mechanism to avoid using macros or code generation.\
Contrary to C++ or rust where functions have to be declared `constexpr` or `const` in order to be called at compile time, in zig everything that can be evaluated at `comptime` just is. A function called from a `comptime` context will either yield an error explaining what part of it isn't able to be evaluated at `comptime` or evaluate the value during compilation. A `comptime` context is for example a constant defined at the global scope, or a `comptime` block.

This can be used to uphold constraints at compile time using assertions:
#sourcecode[```zig
    const FIB_8 = fibonacci(8);
    comptime {
        // won't compile
        std.debug.assert(fibonacci(3) == 1);
    }

    fn fibonacci(comptime N: usize) u64 {
        if (N == 0 or N == 1) {
            return 1;
        }
        var a = 1;
        var b = 1;
        for (1..N) |_| {
            const c = a + b;
            a = b;
            b = c;
        }
        return b;
    }
```]

This means, if the main function is able to be evaluated at compile time, and it is called from a comptime context, the zig compiler acts as an interpreter and the program is executed when it is built. Granted since comptime code can't perform I/O there aren't really much useful things that can be done in such a program.

Arguments to functions can be declared as `comptime` which requires them to be known during compilation. This is often used for types passed to function in the same way other languages handle generics. Considering the following Kotlin class:
#sourcecode[```kotlin
    class Container<T>(
        var items: ArrayList<T>,
    )
```]
An equivalent zig struct would be defined as a function taking a `comptime` type as an argument that returns another type.
#sourcecode[```zig
    fn Container(comptime T: type) type {
        return struct {
            items: ArrayList(T),
        }
    }
```]
Note that ArrayList is another such function defined in the std library.

== SIMD
In addition to the automatic vectorization of code that the LLVM optimizer does, zig also provides a way to explicitly define vector operations that will compile down to target specific SIMD operations.
#sourcecode[```zig
    const a = @Vector(4, i32){ 1, 2, 3, 4 };
    const b = @Vector(4, i32){ 5, 6, 7, 8 };
    const c = a + b;
```]

== Eco system
- minimal standard library
    - no unicode string support, only functions for operating on slices e.g. std.mem
    - utf-8 string libraries are 3rd party
- somewhat immature ecosystem
    - missing regex library
    - async not available in `0.11` self-hosted compiler
Compared to C++, Java, or Rust the std library of zig is quite minimal.
Neither the zig language itself, nor the std library provide a datatype for strings. String literals are represented as byte slices (`[]const u8`), which allows using the whole range of `std.mem.*` functions to operate on them. There is no unicode support.

= Development process
Since the scope of the program was predetermined, the main focus was on performance.

The zig std library provides `IterableDir`, an iterator for iterating a directory in a depth first manner, but unfortunately that approach doesn't allow filtering of searched directories. To overcome that limitation I mostly copied the std library function for iterating directories and modified it slightly to allow filtering out hidden directories.

There are some beginnings of regex libraries written in zig, but they are still in their infancy, and aren't ready to be used right now. So I decided on using the rust regex library (`rure`) through it's C API, since it's a standalone project, without tethers to a standard library, and reasonable fast.\
To include a C library, some modification inside the `build.zig` configuration file are needed: 
#sourcecode[```zig
    // link all the other stuff needed
    exe.linkLibC();
    exe.linkSystemLibrary("util");
    exe.linkSystemLibrary("dl");
    exe.linkSystemLibrary("gcc_s");
    exe.linkSystemLibrary("m");
    exe.linkSystemLibrary("rt");
    exe.linkSystemLibrary("util");
    // link rure itself
    exe.addIncludePath(LazyPath.relative("rure/regex-capi/include"));
    exe.addLibraryPath(LazyPath.relative("rure/target/release"));
    exe.linkSystemLibrary2("rure", .{ .needed = true, .preferred_link_mode = .Static });
```]
This links the `rure` crate and all it's dependencies statically into the final binary.

The dependencies are taken straight from the `rure` compile script:
#sourcecode[```sh
    # N.B. Add `--release` flag to `cargo build` to make the example run faster.
    cargo build --manifest-path ../Cargo.toml
    gcc -O3 -DDEBUG -o iter iter.c -ansi -Wall -I../include -L../../target/debug -lrure
    # If you're using librure.a, then you'll need to link other stuff:
    # -lutil -ldl -lpthread -lgcc_s -lc -lm -lrt -lutil -lrure
```]

When linking C libraries, zig isn't able to include debug symbols, so crash messages that would normally be informative, only show memory addresses:
#sourcecode[```
thread 20843 panic: index out of bounds: index 14958, len 14948
Unwind error at address `:0x2ebaef` (error.InvalidDebugInfo), trace may be incomplete
```]
This is a known bug.

== Single threaded optimization
=== Line by line matching
To keep it simple the first implementation, read the whole file into a single buffer and ran a compiled regex pattern match on every line. This was done using a regex iterator from the `rure` crate.

=== Whole text matching for performance
After some investigation it turned out that initializing the regex search iterator provided by the `rure` crate had more overhead than expected, and running the regex pattern match on the whole text instead of every line would improve performance significantly. After the previous change, I found out that the `rure` library provided a function that allowed setting the start index for searching inside the passed text slice. Using this function avoided allocating the iterator in the first place.

=== Line by line matching with fixed size buffer
Since one of the tests was to search an 8gb large text file, the input would need to be split up into smaller chunks as to avoid running out of memory. This was done using a fixed size buffer which would only load part of the file, searching that buffer up to the last fully included line, then moving the unsearched parts including possibly relevant context lines to the start of the buffer, and eventually refilling the buffer with remaining data to search. Since lines need to be iterated to calculate line numbers, and the I discovered the `rure` function that searches the text directly I decided to once again search each line individually, instead of the whole text.

=== Whole text matching for performance with fixed size buffer
After further investigation it turned out that the overhead of searching each line didn't just come from  the `rure` iterator, but some special regex patterns introduced large overhead anyway when starting the search. One example was the word character pattern `\w`, which respect possibly multi-byte unicode characters. Since the `rure` library uses a finite automata (state machine), matching multiple word characters results in an exponential explosion of states. Disabling unicode during the regex pattern compilation significantly improved performance. With these findings, the regex pattern matching was once again adjusted to be run on the whole text buffer, to restore previously achieved performance.\
One additional bug that I only tackled at this stage was to prevent regex pattern matches that spanned multiple lines. If a match is found that spans multiple lines an additional search is run only on the fist matched line, if this succeeds too only this match is highlighted and printed.

== Parallelization
At this point most easy wins in single threaded optimization were off the table, so the next performance gain would be using multiple threads. The things that take up the largest portion of time are accessing the file system, and searching the text.

Parallelization was implemented using a thread pool of search workers that would receive file paths using a atomically synchronized message queue. The directory walking remained mostly the same apart from searching files adhoc, they were now sent through the message queue.

The output of multiple threads now had to be synchronized so that lines printed from one file would not be interspersed with other ones.\
There are two obvious solutions to this problem. One is to use a dynamically growing allocated buffer which stores the entire output of a searched file and then write the entire buffer in a synchronized way when the file is fully searched. This would avoid blocking other threads, but could cause the program to run out of memory if large portions of big files would match a search pattern.\
The other solution is to just block output of all other threads once a match has been found in a file and then write all lines directly to stdout. This would avoid running out of memory, but could in worst case scenarios cause basically single threaded performance.\
The final implementation uses a hybrid of the two, each thread has a fixed size output buffer which can be written to without any synchronization. Once the buffer is full access to stdout is locked for other threads until the file is fully searched, but other workers can still access their thread-local output buffers.

Text searching had been parallelized the search workers were now emptying the message queue too quickly, so walking the file system with multiple threads was up next.\
This was heavily influenced by the rust `ignore` by the same author as, and also used in ripgrep. A thread pool of "walkers" is used to search multiple directories simultaneously in a depth first manner to reduce memory consumption.
A walker tries to pop of a directory iterator of a shared atomically synchronized stack, by blocking until one is available. Once it receives a directory it iterates through the remaining entries enqueueing any files encountered. If it encounters a subdirectory, the parent directory is pushed back onto the stack and the subdirectory is walked. Once all walkers are waiting for a new directory iterator all directories have been walked completely and the thread pool is stopped.

== Command line argument parsing
Argument parsing makes use of tagged unions and `comptime`.

There are two different types of arguments: flags and values, both of these are defined as enums. `UserArgFlag`s don't require a value and are just boolean toggles. `UserArgValue`s require a value, for example a number, to be specified after them. `UserArgKind` is a tagged union that either contains one or the other.
#sourcecode[```zig
    const UserArgKind = union(enum) {
        value: UserArgValue,
        flag: UserArgFlag,
    };

    const UserArgValue = enum(u8) {
        Context,
        AfterContext,
        BeforeContext,
    };
    const UserArgFlag = enum(u8) {
        Hidden,
        FollowLinks,
        Color,
        NoHeading,
        IgnoreCase,
        Debug,
        NoUnicode,
        Help,
    };
```]

All user args are defined in an array, including their long form, an optional short form, a description and their union representation.
#sourcecode[```zig
    const USER_ARGS = [_]UserArg{
        .{
            .short = 'A',
            .long = "after-context",
            .kind = .{ .value = .AfterContext },
            .help = "prints the given number of following lines for each match",
        },
        ...
        .{
            .short = null,
            .long = "help",
            .kind = .{ .flag = .Help },
            .help = "print this message",
        },
        ...
    };
```]

When parsing command line arguments this can be used to exhaustively match all possible valid inputs using a switch statement. When adding a new enum variant the compiler enforces it is handled in all switch statements that match the modified enum. This is the simplified switch statements that handles all arguments:
#sourcecode[```zig
    switch (user_arg.kind) {
        .value => |kind| {
            ...

            switch (kind) {
                .Context => {
                    opts.after_context = num;
                    opts.before_context = num;
                },
                ...
            }
        },
        .flag => |kind| {
            ...

            switch (kind) {
                .Hidden => opts.hidden = true,
                ...
            }
        },
    }
```]

The help message is generated at `comptime`, using the list of possible arguments.\
Instead of a general purpose allocator a fixed buffer allocator had to be used, but otherwise the code could be written without taking any precautions.

== Compiler bug
With zig `0.11.0` I encountered a bug in the compiler which would affect command line argument parsing. In debug mode arguments were parsed fine, bug in release mode the `--ignore-case` flag would be parsed as the `--hidden` flag. All flags are defined as an enum:
#sourcecode[```zig
    const UserArgFlag = enum {
        Hidden,
        FollowLinks,
        Color,
        NoHeading,
        IgnoreCase,
        Debug,
        NoUnicode,
        Help,
    };
```]

The issue was fixed by specifying a concrete type to represent the enum instead of letting the compiler infer the type.
#sourcecode[```diff
@@ -27,12 +27,12 @@ const UserArgKind = union(enum) {
     flag: UserArgFlag,
 };

-const UserArgValue = enum {
+const UserArgValue = enum(u8) {
     Context,
     AfterContext,
     BeforeContext,
 };
-const UserArgFlag = enum {
+const UserArgFlag = enum(u8) {
     Hidden,
     FollowLinks,
     Color,
```]

= Conclusion
