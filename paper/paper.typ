#import "template.typ": *

#show: project.with(
  title: "Seminar Programmiersprachen im Verlgeich - Zig",
  author: "Tobias Schmitz",
)

#outline()
#pagebreak()

= Introduction

= Language
- build system
    - same language for build-system
    - build.zig is generated
    - good C interoperability
- manual memory management
    - allocators have to be manually passed
    - deallocate by `defer`ing `deinit` procedures
    - memory leaks are automatically detected in debug mode
- minimal standard library
    - no unicode string support, only functions for operating on slices e.g. std.mem
    - utf-8 string libraries are 3rd party
- exhaustive switch statements
    - useful for enums
- generics are just comptime functions operating on types
- inferred struct literal type `.{}`
- if enum type is known the type can be omitted, `.variant` is sufficient
- errors as values
    - error union explicit or implict
    - try: return on error
    - catch: handle error
- slices
    - pointer and length by default: []u8
    - sentinel terminated, for example null terminated: [\*0]u8
    - exclusive ranges for slicing: my_slice[0..2]
- somewhat immature ecosystem
    - missing regex library
    - async not available in `0.11` self-hosted compiler
- unclear crash messages, even in debug mode
    - just memory addresses
    - this is a bug when linking libc

= Development process

== Single threaded optimization
=== Line by line matching

=== Whole text matching for performance
- to avoid allocating iterator for every line
- then avoid using iterator anyway

=== Line by line matching with fixed size buffer
- no multiline matches
- easier to implement
- lines need to be iterated anyway for line numbers

=== Whole text matching for performance with fixed size buffer
- the rust regex `find` functions has extremely high startup
  overhead on unicode word-character patterns
- avoided to some extend by searching the whole text buffer
  instead of just line by line slices

== Parallelization
- Two worker thread pools
    - One for walking the file tree
    - One for searching files
- Walking the filetree uses a shared stack for depth first searching
- A shared queue is used to pass to be searched files
- A shared sink synchronizes writing to stdout

= Conclusion
