# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.5.1](https://github.com/maidsafe/bls_dkg/compare/v0.5.0...v0.5.1) (2021-08-03)


### Bug Fixes

* Demote `anyhow` and `itertools` to dev-dependencies ([08d0df1](https://github.com/maidsafe/bls_dkg/commit/08d0df118dc90c4f4d60fc8864adc714367e33e6))

## [0.5.0](https://github.com/maidsafe/bls_dkg/compare/v0.4.0...v0.5.0) (2021-06-30)


### ⚠ BREAKING CHANGES

* **blsttc:** this enables blsttc to run on older cpu architectures

### Features

* **blsttc:** update blsttc ([74a2d6b](https://github.com/maidsafe/bls_dkg/commit/74a2d6be20cabc759e5781a11c09fe762bcaf0f6))

## [0.4.0](https://github.com/maidsafe/bls_dkg/compare/v0.3.12...v0.4.0) (2021-06-29)


### ⚠ BREAKING CHANGES

* updates to use blsstc

### Features

* introducing blsstc ([8745c19](https://github.com/maidsafe/bls_dkg/commit/8745c193cf2cc12354f5323871dd63d37b6fe928))

### [0.3.12](https://github.com/maidsafe/bls_dkg/compare/v0.3.11...v0.3.12) (2021-06-28)


### Bug Fixes

* maidsafe version of threshold_crypto ([ee7b3f6](https://github.com/maidsafe/bls_dkg/commit/ee7b3f60458d3233bdf6fb421db938c59020f69f))
* temporary fix for the failure crate deprecation warning ([1f54a21](https://github.com/maidsafe/bls_dkg/commit/1f54a21f1471f153e10318a26d425a05c2eb31c1))
* use blsttc instead of threshold_crypto ([77525c1](https://github.com/maidsafe/bls_dkg/commit/77525c1b7ef636a32d0ecb50e5ade61541e6828e))

### [0.3.11](https://github.com/maidsafe/bls_dkg/compare/v0.3.10...v0.3.11) (2021-06-28)


### Bug Fixes

* tilde reqs ([8f8e3c1](https://github.com/maidsafe/bls_dkg/commit/8f8e3c1dc4d2b1f808ad9faa615e9bde82ce6040))
* upgrade to the latest version of aes crate to remove deprecation warnings ([5b44883](https://github.com/maidsafe/bls_dkg/commit/5b44883c68c89c49ca5cadebc7272151cf06fb5d))

### [0.3.10](https://github.com/maidsafe/bls_dkg/compare/v0.3.9...v0.3.10) (2021-06-14)

### [0.3.9](https://github.com/maidsafe/bls_dkg/compare/v0.3.8...v0.3.9) (2021-05-31)

### [0.3.8](https://github.com/maidsafe/bls_dkg/compare/v0.3.7...v0.3.8) (2021-05-12)


### Bug Fixes

* **key_gen:** if m is set to 0 or 1, we did not detect a threshold ([906ca05](https://github.com/maidsafe/bls_dkg/commit/906ca051584a4c7d1f3f3e9a416dde769748f9e1))

### [0.3.7](https://github.com/maidsafe/bls_dkg/compare/v0.3.6...v0.3.7) (2021-03-03)

### [0.3.6](https://github.com/maidsafe/bls_dkg/compare/v0.3.5...v0.3.6) (2021-02-25)

### [0.3.5](https://github.com/maidsafe/bls_dkg/compare/v0.3.4...v0.3.5) (2021-02-09)

### [0.3.4](https://github.com/maidsafe/bls_dkg/compare/v0.3.3...v0.3.4) (2021-02-03)

### [0.3.3](https://github.com/maidsafe/bls_dkg/compare/v0.3.2...v0.3.3) (2021-01-20)

### [0.3.2](https://github.com/maidsafe/bls_dkg/compare/v0.3.1...v0.3.2) (2021-01-13)

### [0.3.1](https://github.com/maidsafe/bls_dkg/compare/v0.3.0...v0.3.1) (2021-01-04)

## [0.3.0](https://github.com/maidsafe/bls_dkg/compare/v0.2.2...v0.3.0) (2021-01-04)


### ⚠ BREAKING CHANGES

* use thiserror and remove members

### api

* use thiserror and remove members ([4d4b7c5](https://github.com/maidsafe/bls_dkg/commit/4d4b7c5fb9209d0d30b26499d254dc37d9965342))

### [0.2.2](https://github.com/maidsafe/bls_dkg/compare/v0.2.1...v0.2.2) (2020-11-18)

### [0.2.1](https://github.com/maidsafe/bls_dkg/compare/v0.2.0...v0.2.1) (2020-10-05)

## [0.2.0](https://github.com/maidsafe/bls_dkg/compare/v0.1.5...v0.2.0) (2020-10-01)


### ⚠ BREAKING CHANGES

* the commit before changed API to use XorName as
participants indexing key, instead of generic type with traits.
This commit is just to trigger a major version update.

### Features

* using XorName as participants key ([2b617a2](https://github.com/maidsafe/bls_dkg/commit/2b617a24d6bdd3d8dd8200f76e7f27053fa02dec))

### [0.1.5](https://github.com/maidsafe/bls_dkg/compare/v0.1.4...v0.1.5) (2020-10-01)

### [0.1.4](https://github.com/maidsafe/bls_dkg/compare/v0.1.3...v0.1.4) (2020-09-30)

### [0.1.3](https://github.com/maidsafe/bls_dkg/compare/v0.1.2...v0.1.3) (2020-09-30)

### [0.1.2](https://github.com/maidsafe/bls_dkg/compare/v0.1.1...v0.1.2) (2020-09-30)

### [0.1.1](https://github.com/maidsafe/bls_dkg/compare/v0.1.0...v0.1.1) (2020-09-21)

### [0.1.0](https://github.com/maidsafe/bls_dkg/compare/v0.1.0...v0.1.0) (2020-08-31)
* Initial implementation
