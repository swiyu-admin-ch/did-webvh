#!/usr/bin/env bash

cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdid_tdw.so --language python --out-dir bindings/python
cp target/release/libdid_tdw.so bindings/python