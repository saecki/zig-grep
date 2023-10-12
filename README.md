# seminar-pl-zig-grep

## Build & Run
- Install the [zig toolchain](https://ziglang.org/download)
- `zig build run`

## Notes
- manual memory management
    - allocators have to be manually passed
    - deallocate by `defer`ing `deinit` procedures
    - memory leaks are automatically detected in debug mode
- exhaustive switch statements
    - useful for enums
- generics are just comptime functions operating on types
