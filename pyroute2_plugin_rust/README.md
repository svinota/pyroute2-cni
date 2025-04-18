# pyroute2-cni-plugin

A Rust implementation of the pyroute2 CNI plugin.

## Building

```bash
cargo build --release
```

The compiled binary will be available at `target/release/pyroute2-cni-plugin`.

## Installation

1. Build the plugin
2. Copy it to the CNI plugins directory:

```bash
sudo cp target/release/pyroute2-cni-plugin /opt/cni/bin/
```

## License

[Your license information here]