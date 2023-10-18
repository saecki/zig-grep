# seminar-pl-zig-grep

## Build & Run
- Install the [zig toolchain](https://ziglang.org/download)
- Install the [rust toolchain](https://rustup.rs/)
- Initialize the rust regex (`rure`) submodule `git submodule init rure`
- Build the `rure` crate `cargo build --release --manifest-path=rure/regex-capi/Cargo.toml`
- Build and run the program `zig build -Doptimize=ReleaseFast run -- -c "rure([a-zA-Z_]*)" src`
- The executable should now be at `zig-out/bin/zig-grep`

## Notes
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
    - sentinel terminated, for example null terminated: [*0]u8
    - exclusive ranges for slicing: my_slice[0..2]
- somewhat immature ecosystem
    - missing regex library
- unclear crash messages, even in debug mode
    - just memory addresses
