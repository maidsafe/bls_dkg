# BLS-DKG
Implementation of a BLS DKG mechanism, requires signing key, encryption key and SocketAddr of participants 

Based on the exellent description as found [here](https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md#distributed-key-generation-dkg-protocol). This implementation forces participation and honesty. Therefor it can be used in hostile and friendly environments where `m` must be `<=n`. The participant id's must be sortable to allow all patricipants to select the same (threshold + 1) `t+1` participants in key generation. 

The notion is that all participants (p) agree on `p` and `m` (members) of `n` (total number of members). The participants must be able to renew their encryption key. This will be used in a `complain + justiication` message. That message will prove a participant sent encrypted junk to another member. The member complaining will have to expose their encryptoin keypair and also renew it in a single message. This will require a `sign(complaint, justification, new encrypt_public_key)` message. At this time the DKG is aborted and the complainer or the participant who sent the message will be excluded in the next round. Prior to the next round happening a new participant can be added to maintain a constant number of participants. 

This algorithm is syncronous and will require participants are disqualified for sending bad data **or** being non responsive. The latter is arbitralily set in this crate, but it can be set by users of the crate.



