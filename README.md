# seminar-pl-zig-grep

## Build & Run
- Install the [zig toolchain](https://ziglang.org/download)
- Install the [rust toolchain](https://rustup.rs/)
- Initialize the rust regex (`rure`) submodule `git submodule init rure`
- Build the `rure` crate `cargo build --release --manifest-path=rure/regex-capi/Cargo.toml`
- Build and run the program `zig build run -- "rure([a-zA-Z_]*)" src`

## Notes
- manual memory management
    - allocators have to be manually passed
    - deallocate by `defer`ing `deinit` procedures
    - memory leaks are automatically detected in debug mode
- exhaustive switch statements
    - useful for enums
- generics are just comptime functions operating on types
- inferred struct literal type `.{}`
- if enum type is known the type can be omitted, `.variant` is sufficient
- errors as values
    - error union explicit or implict
    - try: return on error
    - catch: handle error
