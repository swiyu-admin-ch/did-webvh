#!/usr/bin/env bash

cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdid_tdw.so --language kotlin --out-dir bindings/kotlin
cp target/release/libdid_tdw.so bindings/kotlin