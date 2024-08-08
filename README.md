# zig-grep

## Build & Run
- Install the [zig toolchain](https://ziglang.org/download)
- Install the [rust toolchain](https://rustup.rs/)
- Initialize the rust regex (`rure`) submodule `git submodule init rure`
- Build the `rure` crate `cargo build --release --manifest-path=rure/regex-capi/Cargo.toml`
- Build and run the program `zig build -Doptimize=ReleaseFast run -- -c "rure([a-zA-Z_]*)" src`
- The executable should now be at `zig-out/bin/zig-grep`

## Build Paper
- Install [typst](https://typst.app)
- Build the paper `typst compile paper/paper.typ`
