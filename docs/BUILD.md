# Build

Requires Rust stable (developed on 1.94).

```sh
cargo test                                   # all core tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
rustup target add x86_64-pc-windows-msvc
cargo check --target x86_64-pc-windows-msvc  # type-check core for Windows
```

Run the filter locally without changing the system (any OS):

```sh
export GG_DATA_DIR=./gg-data
cargo run -p gg-windows-service -- console --listen 127.0.0.1:5353 &
cargo run -p gg-windows-service -- rules add example-gambling-domain.com
cargo run -p gg-windows-service -- status
```

Only clients pointed at that address are filtered. Nothing system-wide changes.
