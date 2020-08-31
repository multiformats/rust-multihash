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
tiny-multihash = "*"
```

Then run `cargo build`.

## Usage

```rust
use tiny_multihash::{Multihash, MultihashDigest, SHA2_256};

fn main() {
    let hash = Multihash::new(SHA2_256, b"my hash");
    println!("{:?}", hash);
}
```

### Using a custom code table

You can derive your own application specific code table:

```rust
use tiny_multihash::derive::Multihash;
use tiny_multihash::{Hasher, MultihashDigest};

const FOO: u64 = 0x01;
const BAR: u64 = 0x02;

#[derive(Clone, Debug, Eq, Multihash, PartialEq)]
pub enum Multihash {
    #[mh(code = FOO, hasher = tiny_multihash::Sha2_256)]
    Foo(tiny_multihash::Sha2Digest<tiny_multihash::U32>),
    #[mh(code = BAR, hasher = tiny_multihash::Sha2_512)]
    Bar(tiny_multihash::Sha2Digest<tiny_multihash::U64>),
}

fn main() {
    let hash = Multihash::new(FOO, b"my hash");
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
