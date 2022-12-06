# [v0.18.0](https://github.com/multiformats/rust-multihash/compare/v0.17.0...v) (2022-12-06)


### Bug Fixes

* remove Nix support ([#254](https://github.com/multiformats/rust-multihash/issues/254)) ([ebf57dd](https://github.com/multiformats/rust-multihash/commit/ebf57ddb82be2d2fd0a2f00666b0f888d4c78e1b)), closes [#247](https://github.com/multiformats/rust-multihash/issues/247)
* update to Rust edition 2021 ([#255](https://github.com/multiformats/rust-multihash/issues/255)) ([da53376](https://github.com/multiformats/rust-multihash/commit/da53376e0d9cf2d82d6c0d10590a77991cb3a6b6))


### Features

* add `encoded_len` and bytes written ([#252](https://github.com/multiformats/rust-multihash/issues/252)) ([b3cc43e](https://github.com/multiformats/rust-multihash/commit/b3cc43ecb6f9c59da774b094853d6542430d55ad))


### BREAKING CHANGES

* update to Rust edition 2021
* `Multihash::write()` returns bytes written

    Prior to this change it returned an empty tuple `()`, now it returns
the bytes written.
