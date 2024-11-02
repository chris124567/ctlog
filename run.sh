#!/bin/sh
set -eux

cargo fmt
cargo run --release
