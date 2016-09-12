# rust-multihash

[![Build Status](https://img.shields.io/travis/multiformats/rust-multihash/master.svg?style=flat-square)](https://travis-ci.org/multiformats/rust-multihash)
[![](https://img.shields.io/badge/rust-docs-blue.svg?style=flat-square)](http://dignifiedquire.github.io/rust-multihash/multihash/struct.Multihash.html)
[![](https://img.shields.io/badge/made%20by-Protocol%20Labs-blue.svg?style=flat-square)](http://ipn.io)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](http://github.com/multiformats/multiformats)
[![](https://img.shields.io/badge/freenode-%23ipfs-blue.svg?style=flat-square)](http://webchat.freenode.net/?channels=%23ipfs)

> [multihash](https://github.com/multiformats/multihash) implementation in Rust.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Supported Hash Types](#supported-hash-types)
- [Dependencies](#dependencies)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

```
TODO
```

## Usage

First add this to your `Cargo.toml`

```toml
[dependencies]
multihash = "*"
```

```rust
crate extern multihash

use multihash::{encode, decode, HashType};

let hash = encode(HashTpype:SHA2256, "my hash").unwrap();
let multi = decode(&hash).unwrap();
```

## Supported Hash Types

* `SHA2 256`
* `SHA2 512`


## Dependencies

This uses [libsodium](https://github.com/jedisct1/libsodium) and [sodiumoxide](https://github.com/dnaq/sodiumoxide)
for the hashing so it depends on libsodium being installed.

## Maintainers

Captain: [@dignifiedquire](https://github.com/dignifiedquire).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/multiformats/rust-multihash/issues).

Check out our [contributing document](https://github.com/multiformats/multiformats/blob/master/contributing.md) for more information on how we work, and about contributing in general. Please be aware that all interactions related to multiformats are subject to the IPFS [Code of Conduct](https://github.com/ipfs/community/blob/master/code-of-conduct.md).

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.


## License

[MIT](LICENSE)
