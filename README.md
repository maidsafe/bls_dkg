# BLS DKG

Implementation of a BLS DKG mechanism, requires signing key, encryption key and SocketAddr of participants.

Based on the excellent description as found [here](https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md#distributed-key-generation-dkg-protocol). This implementation forces participation and honesty. Therefore it can be used in hostile and friendly environments where `m` must be `<=n`. The participant IDs must be sortable to allow all participants to select the same (threshold + 1) `t+1` participants in key generation.

The notion is that all participants (p) agree on `m` (members) of `n` (total number of members). The participants must be able to renew their encryption key. This will be used in a `complain + justification` message. That message will prove a participant sent encrypted junk to another member. The member justifying a complaint will have to expose their encryption keypair and also renew it in a single message. This will require a `sign(complaint, justification, new encrypt_public_key)` message. At this time the DKG is aborted and the complainer or the participant who sent the message will be excluded in the next round. Prior to the next round happening a new participant can be added to maintain a constant number of participants.

This algorithm is synchronous and will require participants are disqualified for sending bad data **or** being non responsive. The latter is arbitrarily set in this crate, but it can be set by users of the crate.

| [Documentation](https://maidsafe.github.io/bls_dkg/) | [MaidSafe website](https://maidsafe.net) | [Safe Dev Forum](https://forum.safedev.org) | [Safe Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## License

This Safe Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) http://opensource.org/licenses/MIT) at your option.

## Contributing

Want to contribute? Great :tada:

There are many ways to give back to the project, whether it be writing new code, fixing bugs, or just reporting errors. All forms of contributions are encouraged!

For instructions on how to contribute, see our [Guide to contributing](https://github.com/maidsafe/QA/blob/master/CONTRIBUTING.md).
