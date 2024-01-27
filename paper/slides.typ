#import "slides-template.typ": *

#let title = "Writing a grep like program in Zig"
#let author = "Tobias Schmitz"

#let primary-color = rgb("#f7a43d")
#let primary-dimmed-color = rgb("#403c38")
#let footer-a-color = rgb("#f7a43d")
#let footer-b-color = rgb("#fcca79")
#let dark-surface = rgb("#202020")

#show: project.with(
  aspect-ratio: "16-9",
  bg-color: dark-surface,
  primary-color: primary-color,
  primary-dimmed-color: primary-dimmed-color,
  footer-a-color: footer-a-color,
  footer-b-color: footer-b-color,
  short-author: author,
  short-title: title,
  short-date: datetime.today().display(),
  progress-bar: true,
)

#title-slide(
  title: [
    Writing a grep like\
    program in Zig
  ],
  subtitle: "Seminar Programming Languages",
  authors: (author),
  institution-name: "University of Siegen",
)

#slide(title: "Contents")[
  #text(size: 1em, "Language")\
  #text("  About")\
  #text("  Error Handling")\
  #text("  Comptime")\
  #text("  Defer")\
  #v(0.2em)
  #text(size: 1em, "Program")\
  #text("  Synchronization")\
  #text("  Compiler Bug")\
  #text("  Benchmarks")\
]

#focus-slide(background-color: dark-surface, new-section: "Language")[
  #align(center)[
    #image("zig-logo-light.svg", width: 60%)
  ]
]

#slide(title: "About")[
  Compiled
  #v(1em)
  General Purpose
  #v(1em)
  Systems Programming Language
]

#slide(title: "About")[
  Successor to C
  #v(1em)
  Focus on readability
  #v(1em)
  and maintainability
]

#slide(title: "About")[
  Appeared 2016
  #v(1em)
  Written by Andrew Kelley
  #v(1em)
  Zig Software Foundation (ZSF)
]

#slide(title: "Error Handling")[
  No exceptions
  #v(1em)
  Errors as values
  #v(1em)
  Error sets and unions
]

#walk-through-slides(
  title: "Error Handling",
  code-parts: (
    ```zig
      // inferred error set
      pub fn main() !void {
    ```,
    ```zig
          const num = try parseInt(u32, "324", 10);
    ```,
    ```zig
      }
    ```,
    ```zig

      // named error set
      const IntError = error{
          IsNull,
          Invalid,
      };
    ```,
    ```zig
      fn checkNull(num: usize) IntError!void {
    ```,
    ```zig
          if (num == 0) {
              return error.IsNull;
          }
    ```,
    ```zig
      }
    ```,
  ),
  highlighted-parts: (
    (0, 2),
    (1,),
    (3,),
    (4,6),
    (5,),
  ),
)

#walk-through-slides(
  title: "Error Handling",
  code-parts: (
    ```zig
      // named error set
      const IntError = error{
          IsNull,
          Invalid,
      };
      fn checkNull(num: usize) IntError!void {
          if (num == 0) {
              return error.IsNull;
          }
      }
    ```,
    ```zig

      switch (checkNull(value))
    ```,
    ```zig
        .IsNull => doOneThing(),
    ```,
    ```zig
        .Invalid => doAnotherThing(),
    ```,
    ```zig
      }
    ```,
  ),
  highlighted-parts: (
    (0,),
    (1,4,),
    (2,),
    (3,),
  ),
)

#walk-through-slides(
  title: "Comptime", 
  code-parts: (
    ```kotlin
      class Container<T>(
          var items: ArrayList<T>,
      )
    ```,
    ```zig

      fn Container(comptime T: type) type {
    ```,
    ```zig
          return struct {
    ```,
    ```zig
              items: ArrayList(T),
    ```,
    ```zig
          }
    ```,
    ```zig
      }
    ```
  ),
  highlighted-parts: (
    (0,),
    (1,5),
    (2,3,4),
    (3,),
  )
)

#slide(title: "Comptime")[
  #code(```zig
    pub fn ArrayList(comptime T: type) type {
        return ArrayListAligned(T, null);
    }
  ```)
]

#walk-through-slides(
  title: "Comptime", 
  code-parts: (
    ```zig
    fn fibonacci(n: usize) u64 {
        if (n == 0 or n == 1) {
            return 1;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
    ```,
    ```zig

    const FIB_8 = fibonacci(8);
    ```,
    ```zig

    comptime {
        // won't compile
        std.debug.assert(fibonacci(3) == 1);
    }
    ```,
  ),
  highlighted-parts: (
    (0,),
    (1,),
    (2,),
  )
)

#slide(title: "Comptime")[
  #set text(size: 16pt)
  #code-space()
  #text(fill: rgb("#8ec07c"), "Build Summary:") 0/3 steps succeeded; 1 failed #text(fill: luma(120), "(disable with --summary none)")\
  install #text(fill: luma(120), "transitive failure")\
  └─ install zig-demo #text(fill: luma(120), "transitive failure")\
  #text("   ")└─ zig build-exe zig-demo Debug native #text(fill: red, "1 errors")\
  zig/0.11.0/files/lib/std/debug.zig:343:14: #text(fill: red, "error:") reached unreachable code\
  #text("    ")if (!ok) unreachable; #text(fill: luma(120), "// assertion failure")\
  #text("             ")#text(fill: rgb("#b8bb26"), "^~~~~~~~~~~")\
  src/main.zig:13:21: note: called from here\
  #text("    ")std.debug.assert(fibonacci(3) == 1);\
  #text("    ")#text(fill: rgb("#b8bb26"), "~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~")\
]

#slide(title: "Comptime")[
  #set text(size: 16pt)
  #dimmed-code[```
  Build Summary: 0/3 steps succeeded; 1 failed (disable with --summary none)
  install transitive failure
  └─ install zig-demo transitive failure
     └─ zig build-exe zig-demo Debug native 1 errors
  zig/0.11.0/files/lib/std/debug.zig:343:14: error: reached unreachable code
      if (!ok) unreachable; // assertion failure
               ^~~~~~~~~~~
  ```]
  #v(0fr)
  #v(0.65em)
  src/main.zig:13:21: note: called from here\
  #text("    ")std.debug.assert(fibonacci(3) == 1);\
  #text("    ")#text(fill: rgb("#b8bb26"), "~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~")\
]

#slide(title: "Comptime")[
  #set text(size: 16pt)
  #dimmed-code[```
  Build Summary: 0/3 steps succeeded; 1 failed (disable with --summary none)
  install transitive failure
  └─ install zig-demo transitive failure
     └─ zig build-exe zig-demo Debug native 1 errors
  ```]
  #v(0fr)
  #v(0.65em)
  zig/0.11.0/files/lib/std/debug.zig:343:14: #text(fill: red, "error:") reached unreachable code\
  #text("    ")if (!ok) unreachable; #text(fill: luma(120), "// assertion failure")\
  #text("             ")#text(fill: rgb("#b8bb26"), "^~~~~~~~~~~")\
  #v(0fr)
  #v(0.23em)
  #dimmed-code[```
  src/main.zig:13:21: note: called from here
      std.debug.assert(fibonacci(3) == 1);
      ~~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
  ```]
]

#walk-through-slides(
  title: "Comptime", 
  code-parts: (
    ```zig
    fn fibonacci(n: usize) u64 {
        if (n == 0 or n == 1) {
            return 1;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
    ```,
    ```zig

    const FIB_8 = fibonacci(8);
    ```,
    ```zig

    comptime {
        // won't compile
        std.debug.assert(fibonacci(3) == 1);
    }
    ```,
  ),
  highlighted-parts: (
    (2,),
  )
)

#walk-through-slides(
  title: "Comptime", 
  code-parts: (
    ```zig
    fn fibonacci(n: usize) u64 {
        if (n == 0 or n == 1) {
            return 1;
        }
        return fibonacci(n - 1) + fibonacci(n - 2);
    }
    ```,
    ```zig

    const FIB_8 = fibonacci(8);
    ```,
    ```zig

    comptime {
        // but this will
        std.debug.assert(fibonacci(3) == 3);
    }
    ```,
  ),
  highlighted-parts: (
    (2,),
  )
)

#slide(title: "Defer")[
  Execute code at scope exit
  #v(1em)
  Clean up resources
]

#walk-through-slides(
  title: "Defer", 
  code-parts: (
    ```zig
      fn main() !void {
    ```,
    ```zig
          var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    ```,
    ```zig
          defer _ = gpa.deinit();
    ```,
    ```zig
          const allocator = gpa.allocator();
    ```,
    ```zig

          var input_paths = ArrayList([]const u8).init(allocator);
    ```,
    ```zig
          defer input_paths.deinit();
    ```,
    ```zig

          const pattern = try parseArgs(&input_paths) orelse {
              return;
          };
    ```,
    ```zig

          // 1. input_paths.deinit();
          // 2. _ = gpa.deinit();
    ```,
    ```zig
      }
    ```,
  ),
  highlighted-parts: (
    (1,2),
    (2,),
    (4,5),
    (5,),
    (6,),
    (2,5,7),
  )
)

#focus-slide(background-color: dark-surface, new-section: "Program")[
  #align(center)[
    = Program
  ]
]

#slide(title: "Synchronization")[
  #code[```zig
    const AtomicQueue = struct {
        mutex: std.Thread.Mutex,
        state: std.atomic.Atomic(State),
        buf: []T,
    }
  ```]
]
  
#slide(title: "Synchronization")[
  Futex: fast userspace mutex

  #quote("A futex consists of a kernel-space wait queue that is attached to an atomic integer in userspace")
]

#slide(title: "Synchronization")[
  #code[```zig
    const State = enum(u32) {
        Empty,
        NonEmpty,
        Full,
    };
  ```]
  #dimmed-code[```zig

    const AtomicQueue = struct {
        mutex: std.Thread.Mutex,
  ```]
  #code[```zig
        state: std.atomic.Atomic(State),
  ```]
  #dimmed-code[```zig
        buf: []T,
    }
  ```]
]

#walk-through-slides(
  title: "Synchronization",
  code-parts: (
  ```zig
    pub fn append(self *AtomicQueue, item: T) void {
  ```,
  ```zig
        self.mutex.lock();
  ```,
  ```zig
        defer self.mutex.unlock();
  ```,
  ```zig

        if (self.len >= self.buf.len) {
  ```,
  ```zig
            self.mutex.unlock();
            Futex.wait(&self.state, State.Full);
            self.mutex.lock();
  ```,
  ```zig
        }
  ```,
  ```zig

        self.buf.append(item)
  ```,
  ```zig

        const new_state: State = .NonEmpty;
        self.state.store(new_state, Ordering.SeqCst);
  ```,
  ```zig
        Futex.wake(&self.state, 1);
  ```,
  ```zig
    }
  ```,
  ),
  highlighted-parts: (
    (0,9),
    (1,2),
    (2,),
    (3,5),
    (4,),
    (6,),
    (7,),
    (8,),
    (2,9),
  ),
)

#walk-through-slides(
  title: "Compiler Bug",
  code-parts: (
    ```zig
      const UserArgFlag = enum {
    ```,
    ```zig
          Hidden,
    ```,
    ```zig
          FollowLinks,
          Color,
          NoHeading,
    ```,
    ```zig
          IgnoreCase,
    ```,
    ```zig
          Debug,
          NoUnicode,
          Help,
      };
    ```
  ),
  highlighted-parts: (
    (0, 1, 2, 3, 4),
    (1, 3),
  ),
)

#slide(title: "Compiler Bug")[
  #code[```diff
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
]

#slide(title: "Compiler Bug")[
  #dimmed-code[```zig
    const UserArgFlag = enum {
  ```]
  #code[```zig
        Hidden,
  ```]
  #dimmed-code[```zig
        FollowLinks,
        Color,
        NoHeading,
  ```]
  #code[```zig
        IgnoreCase,
  ```]
  #dimmed-code[```zig
        Debug,
        NoUnicode,
        Help,
    };
  ```]

  `0b100` truncated to `0b00`?
  
  bug already fixed on master
]


#slide(title: "Benchmarks")[
  Run using hyperfine
  #v(1em)
  On testsuite
  #v(1em)
  2-3x slower than ripgrep
]

#slide(title: "Results R5 5600x & 32Gb")[
  #image("result_desktop_r5_5600x_32gb_linux.svg")
]

#slide(title: "Results R7 5800u & 16Gb")[
  #image("result_thinkpad_r7_5800u_16gb_linux.svg")
]

#slide(title: "Results R5 5600x & 32Gb")[
  #image("result_desktop_r5_5600x_32gb_subtitles.svg")
]

#slide(title: "Results R7 5800u & 16Gb")[
  #image("result_thinkpad_r7_5800u_16gb_subtitles.svg")
]

#focus-slide(background-color: dark-surface, new-section: none)[
  #align(center)[
    = Questions?
  ]
]
