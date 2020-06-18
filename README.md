# tiny-multihash

[![Crates.io](https://img.shields.io/crates/v/multihash?style=flat-square)](https://crates.io/crates/tiny-multihash)
[![Documentation](https://docs.rs/multihash/badge.svg?style=flat-square)](https://docs.rs/tiny-multihash)

> [multihash](https://github.com/multiformats/multihash) implementation in Rust.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Supported Hash Types](#supported-hash-types)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

First add this to your `Cargo.toml`

```toml
[dependencies]
multihash = "*"
```

Then run `cargo build`.

## Usage

```rust
use multihash::Code;

fn main() {
    let hash = Code::Sha2_256.digest(b"my hash");
    println!("{:?}", hash);
}
```

## Supported Hash Types

* `SHA1`
* `SHA2-256`
* `SHA2-512`
* `SHA3`/`Keccak`
* `Blake2b-256`/`Blake2b-512`/`Blake2s-128`/`Blake2s-256`

## Maintainers

[@dvc94ch](https://github.com/dvc94ch)
