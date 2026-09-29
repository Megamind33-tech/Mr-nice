# Build

Requires Rust stable (developed on 1.94).

```sh
cargo test                                   # all core tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
rustup target add x86_64-pc-windows-msvc
cargo check --target x86_64-pc-windows-msvc  # type-check core for Windows
```

Windows service and Android app build steps will be added with those components.
