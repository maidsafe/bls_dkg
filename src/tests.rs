// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[cfg(test)]
mod test {
    use crate::key_gen::Phase;
    use crate::member::NodeID;
    use crate::Member;
    use bincode::serialize;
    use itertools::Itertools;
    use rand::Rng;
    use std::collections::{btree_set::BTreeSet, BTreeMap, HashMap};
    use std::net::SocketAddr;
    use std::thread::sleep;
    use std::time::Duration;

    const NODE_NUM: usize = 7;
    const THRESHOLD: usize = 5;

    fn setup_members_and_init_dkg(
        num: usize,
        non_responsives: BTreeSet<usize>,
    ) -> (Vec<NodeID>, Vec<Member>) {
        let (ids, mut members, _addrs, map) = create_members(num);

        initialize_dkg(&mut members, map, non_responsives, THRESHOLD);

        (ids, members)
    }

    fn create_members(
        num: usize,
    ) -> (
        Vec<NodeID>,
        Vec<Member>,
        Vec<SocketAddr>,
        HashMap<NodeID, SocketAddr>,
    ) {
        let mut member_vec = vec![];
        let mut id_vec = vec![];
        let mut socket_addr = vec![];
        let mut map = HashMap::new();

        for _ in 0..num {
            let (member, addr, id) = Member::new_for_test().unwrap();
            member_vec.push(member);
            id_vec.push(id.clone());
            socket_addr.push(addr);
            map.insert(id, addr);
        }

        (id_vec, member_vec, socket_addr, map)
    }

    fn initialize_dkg(
        members: &mut Vec<Member>,
        map: HashMap<NodeID, SocketAddr>,
        non_responsives: BTreeSet<usize>,
        threshold: usize,
    ) {
        let mut proposals = vec![];
        // Initialize DKG for all the Nodes
        for member in members.iter_mut() {
            let proposal = member.init_dkg(map.clone(), threshold).unwrap();
            proposals.push(proposal.clone());
        }

        // Wait for quic connections to connect to each other
        std::thread::sleep(Duration::from_secs(20));

        // Non-responsive members close connections
        for i in 0..members.len() {
            if non_responsives.contains(&i) {
                members[i].set_as_non_responsive();
            }
        }

        // Wait for threads to disconnect successfully
        if !non_responsives.is_empty() {
            sleep(Duration::from_secs(10));
        }

        // Broadcast all the messages simultaneously via multi-threading
        if non_responsives.is_empty() {
            for x in 0..members.len() {
                // Could get delayed during connecting in real-network - keep trying in a loop
                let mut connected = members[x].if_connected_to_all();
                if connected {
                    members[x].broadcast(proposals[x].clone()).unwrap();
                } else {
                    while !connected {
                        connected = members[x].if_connected_to_all();
                        if connected {
                            members[x].broadcast(proposals[x].clone()).unwrap();
                            break;
                        }
                    }
                }
            }
        } else {
            // Do not check for connectivity as non-responsive nodes get disconnected
            for x in 0..members.len() {
                if !non_responsives.contains(&x) {
                    members[x].broadcast(proposals[x].clone()).unwrap();
                }
            }
        }

        // Wait for the Quic threads to finish the DKG process - increases as the number of nodes increase
        let len = members.len();
        if len <= 6 {
            sleep(Duration::from_secs(30));
        } else if len >= 7 && len <= 10 {
            sleep(Duration::from_secs(60));
        } else {
            sleep(Duration::from_secs(90));
        }
    }

    #[test]
    fn member_test() {
        let (_, mut members) = setup_members_and_init_dkg(NODE_NUM, Default::default());

        // Check for Phases, Contributions and Readiness
        for member in members.iter_mut().take(NODE_NUM) {
            assert!(member.all_contribution_received().unwrap());
            assert_eq!(Phase::Finalization, member.phase().unwrap());
            assert!(member.is_ready().unwrap());
        }
    }

    #[test]
    fn threshold_sign_online() {
        let (_, mut members) = setup_members_and_init_dkg(NODE_NUM, Default::default());

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

        let sig_combinations = sig_shares.iter().combinations(THRESHOLD + 1);

        let deficient_sig_combinations = sig_shares.iter().combinations(THRESHOLD);

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
        let (_, mut members) = setup_members_and_init_dkg(NODE_NUM, Default::default());

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

    #[test]
    fn churn_test() {
        let mut rng = rand::thread_rng();

        let initial_num = 3;
        let (_ids, mut members, _addrs, mut map) = create_members(initial_num);

        let mut naming_index = initial_num;

        while naming_index < 15 {
            if members.len() < NODE_NUM {
                // Create a new Node
                let (member, addr, id) = Member::new_for_test().unwrap();
                members.push(member);
                map.insert(id, addr);
                naming_index += 1;
            } else {
                let idx = rng.gen_range(0, members.len());
                let id = members[idx].id();
                members[idx].close();
                let _ = members.remove(idx);
                let _ = assert!(map.remove(&id).is_some());
            }

            let threshold: usize = members.len() * 2 / 3;
            initialize_dkg(&mut members, map.clone(), BTreeSet::new(), threshold);

            assert!(members
                .iter_mut()
                .all(|member| member.generate_keys().is_ok()));
        }
    }
}
