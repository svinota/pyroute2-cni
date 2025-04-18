#!/bin/bash
set -euo pipefail

# Install musl target if not already installed
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

echo "Static binary built at: target/x86_64-unknown-linux-musl/release/pyroute2-cni-plugin"