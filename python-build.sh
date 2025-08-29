#!/usr/bin/env bash

cargo build --release
cargo run --bin uniffi-bindgen generate --library target/release/libdid_webvh.so --language python --out-dir bindings/python
cp target/release/libdid_webvh.so bindings/python