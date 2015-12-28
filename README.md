# rust-multihash

[![Build Status](https://img.shields.io/travis/Dignifiedquire/rust-multihash/master.svg?style=flat-square)](https://travis-ci.org/Dignifiedquire/rust-multihash)
[![](https://img.shields.io/badge/rust-docs-blue.svg?style=flat-square)](http://dignifiedquire.github.io/rust-multihash/multihash/struct.Multihash.html)

> [multihash](https://github.com/jbenet/multihash) implementation in Rust.


## Usage

First add this to your `Cargo.toml`

```toml
[dependencies]
multihash = "*"
```

```rust
crate extern multihash

use multihash::{Multihash, HashType};

let hash = Multihash::new(HashTpype:SHA2256, "my hash").unwrap()

```


## License

[MIT](LICENSE)
