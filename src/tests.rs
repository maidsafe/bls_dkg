// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[cfg(test)]
mod tests {
    use crate::key_gen::Phase;
    use crate::Member;
    use bincode::serialize;
    use itertools::Itertools;
    use quic_p2p::{Config, Peer};
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread::sleep;
    use std::time::Duration;

    pub const IP_LOCAL_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    pub const NODE_NUM: usize = 7;
    pub const THRESHOLD: usize = 6;

    fn setup_members_and_init_dkg(non_responsives: BTreeSet<usize>) -> Vec<Member> {
        let mut node_id_vec = vec![];
        let mut config_vec = vec![];
        let mut socket_addr_vec = vec![];
        let mut peer_vec = vec![];
        let mut map = HashMap::new();
        let mut members = vec![];
        let mut proposals = vec![];

        // Setup Node's transport layer details
        for _ in 0..NODE_NUM {
            let mut config = Config::default();
            config.ip = Some(IP_LOCAL_HOST);
            config.port = Some(0);

            let (member, socket_addr) = Member::new_for_test(config.clone()).unwrap();

            let peer = Peer::Node(socket_addr);
            let id = member.id();

            node_id_vec.push(id);
            config_vec.push(config);
            socket_addr_vec.push(socket_addr);
            peer_vec.push(peer);
            members.push(member);
        }

        // Forms the group - NodeIDs and Socket Addresses.
        for x in 0..NODE_NUM {
            let _ = map.insert(
                node_id_vec[x].clone(),
                (socket_addr_vec[x], peer_vec[x].clone()),
            );
        }

        // Initialize DKG for all the Nodes
        for x in 0..NODE_NUM {
            let proposal = members[x].init_dkg(map.clone(), THRESHOLD).unwrap();
            proposals.push(proposal.clone());
            std::thread::sleep(Duration::from_secs(5));
        }

        // Broadcast all the messages simultaneously via multi-threading
        for x in 0..NODE_NUM {
            if !non_responsives.contains(&x) {
                while members[x].if_connected_to_all() {
                    members[x].broadcast(proposals[x].clone()).unwrap();
                    break;
                }
            }
        }

        // Wait for the Quic threads to finish the DKG process - should be increased if NODENUM is increased
        sleep(Duration::from_secs(90));

        members
    }

    #[test]
    fn member_test() {
        let members = setup_members_and_init_dkg(Default::default());

        // Check for Phases, Contributions and Readiness
        for x in 0..NODE_NUM {
            assert!(members[x].all_contribution_received().unwrap());
            assert_eq!(Phase::Finalization, members[x].phase().unwrap());
            assert!(members[x].is_ready().unwrap());
        }
    }

    #[test]
    fn threshold_sign_online() {
        let mut members = setup_members_and_init_dkg(Default::default());

        let outcome = members[0]
            .generate_keys()
            .expect("Failed to generate `PublicKeySet` for node #0")
            .1;
        let pub_key_set = outcome.public_key_set;

        // Convert members into an ordered BTreeSet for testing.
        let set: BTreeSet<Member> = members.drain(..).collect();

        let msg = "Hello from the group!";
        let sig_shares: BTreeMap<_, _> = set
            .iter()
            .enumerate()
            .map(|(idx, member)| {
                let outcome = member
                    .generate_keys()
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                            idx
                        )
                    })
                    .1;
                let sk = outcome.secret_key_share;
                let pks = outcome.public_key_set;
                assert_eq!(pks, pub_key_set);
                let sig = sk.sign(msg);
                assert!(pks.public_key_share(idx).verify(&sig, msg));
                (idx, sig)
            })
            .collect();

        let sig_combinations = sig_shares.iter().combinations(6 + 1);

        let deficient_sig_combinations = sig_shares.iter().combinations(6);

        for combination in deficient_sig_combinations.clone() {
            match pub_key_set.combine_signatures(combination) {
                Ok(_) => panic!(
                    "Unexpected Success: Signatures cannot be aggregated with THRESHOLD shares"
                ),
                Err(e) => assert_eq!(format!("{:?}", e), "NotEnoughShares".to_string()),
            }
        }

        for combination in sig_combinations.clone() {
            let sig = pub_key_set
                .combine_signatures(combination)
                .expect("signature shares match");
            assert!(pub_key_set.public_key().verify(&sig, msg));
        }

        // Test signatures aggregated from a combination of different share - should be the same
        for signature_shares in sig_combinations.collect_vec().windows(2) {
            let sig = pub_key_set
                .combine_signatures(signature_shares[0].clone())
                .expect("signature shares match");
            let sig_ser =
                serialize(&sig).unwrap_or_else(|_err| b"cannot serialize signature 1".to_vec());
            let sig2 = pub_key_set
                .combine_signatures(signature_shares[1].clone())
                .expect("signature shares match");
            let sig2_ser =
                serialize(&sig2).unwrap_or_else(|_err| b"cannot serialize signature 2".to_vec());
            assert_eq!(sig_ser, sig2_ser);
        }
    }

    #[test]
    fn threshold_encrypt_online() {
        let mut members = setup_members_and_init_dkg(Default::default());

        let pub_key_set = members[0]
            .generate_keys()
            .expect("Failed to generate `PublicKeySet` for node #0")
            .1
            .public_key_set;

        // Convert members into an ordered BTreeSet for testing.
        let set: BTreeSet<Member> = members.drain(..).collect();

        let msg = "Help for threshold encryption unit test!".as_bytes();
        let ciphertext = pub_key_set.public_key().encrypt(msg);

        // Compute the keys and decryption shares.
        let dec_shares: BTreeMap<_, _> = set
            .iter()
            .enumerate()
            .map(|(idx, member)| {
                assert!(member.is_ready().unwrap());
                let outcome = member
                    .generate_keys()
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                            idx
                        )
                    })
                    .1;
                let sk = outcome.secret_key_share;
                let pks = outcome.public_key_set;
                assert_eq!(pks, pub_key_set);
                let dec_share = sk.decrypt_share(&ciphertext).unwrap();
                assert!(pks
                    .public_key_share(idx)
                    .verify_decryption_share(&dec_share, &ciphertext));

                (idx, dec_share)
            })
            .collect();
        // Test threshold encryption verification for a combination of shares - should pass as there
        // are THRESHOLD + 1 shares aggregated in each combination
        let dec_share_combinations = dec_shares.iter().combinations(THRESHOLD + 1);
        for dec_share in dec_share_combinations {
            let decrypted = pub_key_set.decrypt(dec_share, &ciphertext).unwrap();
            assert_eq!(msg, decrypted.as_slice());
        }

        // Test threshold decryption for a combination of shares - shouldn't decrypt as there
        // are THRESHOLD shares in each combination which are not enough to aggregate
        let deficient_dec_share_combinations = dec_shares.iter().combinations(THRESHOLD);
        for deficient_dec_share in deficient_dec_share_combinations {
            match pub_key_set.decrypt(deficient_dec_share, &ciphertext) {
                Ok(_) => {
                    panic!("Unexpected Success: Cannot decrypt by aggregating THRESHOLD shares")
                }
                Err(e) => assert_eq!(format!("{:?}", e), "NotEnoughShares".to_string()),
            }
        }
    }
}
