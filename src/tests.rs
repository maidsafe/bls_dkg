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
    use crate::key_gen::{Error, Phase};
    use crate::member::NodeID;
    use crate::Member;
    use bincode::serialize;
    use bytes::Bytes;
    use itertools::Itertools;
    use quic_p2p::{Config, IncomingConnections, IncomingMessages, QuicP2p};
    use rand::{thread_rng, Rng, RngCore};
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread::sleep;
    use std::time::Duration;

    const NODE_NUM: usize = 7;
    const THRESHOLD: usize = 5;
    const SLEEPING_PERIOD: u64 = 100; // Time(in seconds) required for successful completion of a DKG session with 7 nodes
    pub const IP_LOCAL_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    async fn setup_members_and_init_dkg<R: RngCore>(
        num: usize,
        non_responsives: BTreeSet<usize>,
        rng: &mut R,
    ) -> (Vec<NodeID>, Vec<Member>) {
        let (ids, mut members, map) = create_members(num, rng);

        // Sort them to follow KeyGen's indexing
        members.sort();

        connect_and_initialize_dkg(&mut members, map, non_responsives, THRESHOLD).await;

        (ids, members)
    }

    fn create_members<R: RngCore>(
        num: usize,
        mut rng: &mut R,
    ) -> (Vec<NodeID>, Vec<Member>, HashMap<NodeID, SocketAddr>) {
        let mut member_vec = vec![];
        let mut id_vec = vec![];
        let mut map = HashMap::new();

        for _ in 0..num {
            let mut config = Config::default();
            config.ip = Some(IP_LOCAL_HOST);
            config.port = Some(0);

            let member = Member::new(config, &mut rng).unwrap();
            let id = member.id();
            member_vec.push(member);
            id_vec.push(id.clone());
        }

        // Sort them to follow KeyGen's indexing
        id_vec.sort();
        member_vec.sort();

        // Generate Group's connection details
        for (i, member) in member_vec.iter_mut().enumerate() {
            let addr = member.our_socket_addr();
            map.insert(id_vec[i].clone(), addr);
        }

        (id_vec, member_vec, map)
    }

    async fn connect_and_initialize_dkg(
        members: &mut Vec<Member>,
        map: HashMap<NodeID, SocketAddr>,
        non_responsives: BTreeSet<usize>,
        threshold: usize,
    ) {
        for member in members.iter_mut() {
            member.connect_to_group(map.clone()).await.unwrap();
        }
        println!("Connected Successfully!");

        let mut proposals = vec![];
        // Initialize DKG for all the Nodes
        for member in members.iter_mut() {
            let proposal = member.init_dkg(threshold).unwrap();
            proposals.push(proposal.clone());
        }

        // Non-responsive members close connections
        for (i, member) in members.iter_mut().enumerate() {
            if non_responsives.contains(&i) {
                member.set_as_non_responsive();
                member.disconnect_from_all().await;
            }
        }

        // Broadcast all the messages
        for (x, member) in members.iter_mut().enumerate() {
            if !member.is_non_responsive() {
                member.broadcast(proposals[x].clone()).await.unwrap();
            }
        }

        // Wait for the Quic threads to finish the DKG process
        let len = members.len();
        let barrier = if len <= NODE_NUM {
            SLEEPING_PERIOD
        } else if len > NODE_NUM && len <= NODE_NUM + 3 {
            SLEEPING_PERIOD + 60
        } else {
            SLEEPING_PERIOD + 90
        };
        let mut tick = 0;
        while tick < barrier {
            tick += 1;
            sleep(Duration::from_secs(1));
            if members.iter().all(|member| Ok(true) == member.is_ready()) {
                return;
            }
        }
        panic!("Cannot reach DKG consensus after {:?} seconds", barrier);
    }

    #[tokio::test]
    async fn member_basics_test() {
        let mut rng = thread_rng();
        let (_, mut members) =
            setup_members_and_init_dkg(NODE_NUM, Default::default(), &mut rng).await;

        // Check for Phases, Contributions and Readiness
        for member in members.iter_mut().take(NODE_NUM) {
            assert!(member.all_contribution_received().unwrap());
            assert_eq!(Phase::Finalization, member.phase().unwrap());
            assert!(member.is_ready().unwrap());
        }

        // Convert members into an ordered BTreeSet.
        let set: BTreeSet<Member> = members.drain(..).collect();

        threshold_sign_verification(&set);
        threshold_encrypt_verification(&set);
    }

    fn threshold_sign_verification(set: &BTreeSet<Member>) {
        let pub_key_set = set
            .iter()
            .next()
            .unwrap()
            .generate_keys()
            .expect("Failed to generate `PublicKeySet` for node #0")
            .1
            .public_key_set;

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

    fn threshold_encrypt_verification(set: &BTreeSet<Member>) {
        let pub_key_set = set
            .iter()
            .next()
            .unwrap()
            .generate_keys()
            .expect("Failed to generate `PublicKeySet` for node #0")
            .1
            .public_key_set;

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

    #[tokio::test]
    async fn churn_test() {
        let mut rng = rand::thread_rng();

        let total = 5;
        let initial_num = 2;
        let (_ids, mut members, mut map) = create_members(initial_num, &mut rng);

        let mut rounds = initial_num;

        // Starting with 2 nodes, rounds are incremented when new nodes are added.
        // Testing with less number of nodes and rounds as churns tests can take a while to
        // complete and could block the CI.
        while rounds < total {
            if members.len() < total - initial_num {
                // Create a new Node
                let mut config = Config::default();
                config.ip = Some(IP_LOCAL_HOST);
                config.port = Some(0);

                let member = Member::new(config, &mut rng).unwrap();
                let id = member.id();
                let addr = member.our_socket_addr();
                members.push(member);
                map.insert(id, addr);
                rounds += 1;
            } else {
                // Remove a Node
                let idx = rng.gen_range(0, members.len());
                let id = members[idx].id();
                // Close connections and drop the node.
                members[idx].close().await;
                let _drop_member = members.remove(idx);
                assert!(map.remove(&id).is_some());
            }

            let threshold: usize = members.len() * 2 / 3;
            connect_and_initialize_dkg(&mut members, map.clone(), BTreeSet::new(), threshold).await;

            assert!(members
                .iter_mut()
                .all(|member| member.generate_keys().is_ok()));
        }
    }

    #[tokio::test]
    async fn connectivity() -> Result<(), Error> {
        let mut rng = thread_rng();

        let mut config = Config::default();
        config.ip = Some(IP_LOCAL_HOST);
        config.port = Some(0);

        let mem1 = Member::new(config.clone(), &mut rng)?;

        let mut mem2 = Member::new(config, &mut rng)?;

        let mut map = HashMap::new();
        let _ = map.insert(mem1.id(), mem1.our_socket_addr());
        mem2.connect_to_group(map).await.unwrap();
        Ok(())
    }

    #[tokio::test]
    async fn test_qp2p() -> Result<(), Error> {
        let mut config = Config::default();
        config.ip = Some(IP_LOCAL_HOST);
        config.port = Some(0);

        let qp2p1 = QuicP2p::with_config(Some(config.clone()), VecDeque::new(), false)?;
        let endpoint = qp2p1.new_endpoint()?;

        let mut qp2p2 = QuicP2p::with_config(Some(config), VecDeque::new(), false)?;

        let (e, _conn) = qp2p2.connect_to(&endpoint.local_address()).await?;
        let q1 = endpoint.connect_to(&e.local_address()).await?;
        let mut incoming = e.listen()?;

        q1.send_only(Bytes::copy_from_slice(b"HHELLO WORLD"))
            .await?;
        println!("PRE LOOPPPPP");
        q1.send_only(Bytes::copy_from_slice(
            b"HEYYYYY YOU LIL PIECE OF SHIT YOU BETTER WORK",
        ))
        .await?;
        accept_loop(&mut incoming).await;
        println!("POST LOOPPPP POST MESSAGE");
        q1.send_only(Bytes::copy_from_slice(b"AND THIS TOOOO"))
            .await?;
        sleep(Duration::from_secs(1));
        Ok(())
    }

    async fn accept_loop(incoming: &mut IncomingConnections) {
        while let Some(msg) = incoming.next().await {
            let _handle = tokio::spawn(connection_loop(msg)).await;
        }
    }

    async fn connection_loop(mut stream: IncomingMessages) {
        while let Some(message) = &stream.next().await {
            println!("RECEIVED SOME MESSAGE!");
            match message {
                quic_p2p::Message::UniStream { .. } => {
                    panic!("ERROR: Got Unistream!");
                }
                quic_p2p::Message::BiStream { bytes, .. } => {
                    // let message: Result<Message<NodeID>, Error> = deserialize(&bytes).map_err(|e|Error::Serialization(e.to_string()));
                    println!("GOT MESSAGE: {:?}", bytes.to_ascii_uppercase());
                }
            }
        }
    }
}
