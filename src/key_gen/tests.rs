// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::dev_utils::{create_ids, PeerId, NAMES};
use crate::key_gen::{message::Message, Error, KeyGen};
use bincode::serialize;
use itertools::Itertools;
use rand::{Rng, RngCore};
use std::collections::{BTreeMap, BTreeSet};

// Alter the configure of the number of nodes and the threshold.
const NODENUM: usize = 7;
const THRESHOLD: usize = 5;

fn setup_generators<R: RngCore>(
    mut rng: &mut R,
    non_responsives: BTreeSet<u64>,
) -> (Vec<PeerId>, Vec<KeyGen<PeerId>>) {
    // Generate individual ids.
    let peer_ids: Vec<PeerId> = create_ids(NODENUM);

    (
        peer_ids.clone(),
        create_generators(&mut rng, non_responsives, &peer_ids, THRESHOLD),
    )
}

fn create_generators<R: RngCore>(
    mut rng: &mut R,
    non_responsives: BTreeSet<u64>,
    peer_ids: &[PeerId],
    threshold: usize,
) -> Vec<KeyGen<PeerId>> {
    // Generate individual key pairs.
    let pub_keys: BTreeSet<PeerId> = peer_ids.iter().cloned().collect();

    // Create the `KeyGen` instances
    let mut generators = Vec::new();
    let mut proposals = Vec::new();
    peer_ids.iter().for_each(|peer_id| {
        let key_gen = {
            let (key_gen, proposal) =
                KeyGen::<PeerId>::initialize(&peer_id.sec_key(), threshold, pub_keys.clone())
                    .unwrap_or_else(|err| {
                        panic!("Failed to initialize KeyGen of {:?} {:?}", &peer_id, err)
                    });
            proposals.push(proposal);
            key_gen
        };

        generators.push(key_gen);
    });

    messaging(&mut rng, &mut generators, &mut proposals, non_responsives);

    generators
}

fn messaging<R: RngCore>(
    mut rng: &mut R,
    generators: &mut Vec<KeyGen<PeerId>>,
    proposals: &mut Vec<Message<PeerId>>,
    non_responsives: BTreeSet<u64>,
) {
    // Keep broadcasting the proposals among the generators till no more.
    // The proposal from non_responsive nodes shall be ignored.
    while !proposals.is_empty() {
        let proposals_local = std::mem::replace(proposals, Vec::new());
        for proposal in &proposals_local {
            for (index, generator) in generators.iter_mut().enumerate() {
                if let Ok(proposal_vec) = generator.handle_message(&mut rng, proposal.clone()) {
                    if !non_responsives.contains(&(index as u64)) {
                        proposal_vec
                            .iter()
                            .for_each(|prop| proposals.push(prop.clone()));
                    }
                }
            }
        }
    }
}

#[test]
fn all_nodes_being_responsive() {
    let mut rng = rand::thread_rng();
    let (_, mut generators) = setup_generators(&mut rng, BTreeSet::new());
    // With all participants responding properly, the key generating procedure shall be completed
    // automatically. As when there is no complaint, Justification phase will be triggered directly.
    assert!(generators
        .iter_mut()
        .all(|key_gen| key_gen.generate_keys().is_some()));
}

#[test]
fn having_max_unresponsive_nodes_still_work() {
    let mut rng = rand::thread_rng();
    let mut non_responsives = BTreeSet::<u64>::new();
    for i in 0..(NODENUM - THRESHOLD - 1) as u64 {
        let _ = non_responsives.insert(i);
    }
    let (peer_ids, mut generators) = setup_generators(&mut rng, non_responsives.clone());

    let mut proposals = Vec::new();
    // With one non_responsive node, Proposal phase cannot be completed automatically. This
    // requires finalize_contributing_phase to be called externally to complete the procedure.
    // All participants will transit into Complaint phase afterwards, Then requires
    // finalize_complaining_phase to be called externally to complete the procedure.
    for _ in 0..2 {
        peer_ids.iter().enumerate().for_each(|(index, _peer_id)| {
            if let Ok(proposal_vec) = generators[index].timed_phase_transition(&mut rng) {
                if !non_responsives.contains(&(index as u64)) {
                    for proposal in proposal_vec {
                        proposals.push(proposal);
                    }
                }
            }
        });
        // Continue the procedure with messaging.
        messaging(
            &mut rng,
            &mut generators,
            &mut proposals,
            non_responsives.clone(),
        );
        assert!(proposals.is_empty());
    }

    generators
        .iter_mut()
        .enumerate()
        .for_each(|(index, key_gen)| {
            if !non_responsives.contains(&(index as u64)) {
                assert!(key_gen.generate_keys().is_some());
                non_responsives.iter().for_each(|idx| {
                    assert!(!key_gen.pub_keys().contains(&peer_ids[*idx as usize]))
                });
            } else {
                assert!(key_gen.generate_keys().is_none());
            }
        });
}

#[test]
fn having_min_unresponsive_nodes_cause_block() {
    let mut rng = rand::thread_rng();
    let mut non_responsives = BTreeSet::<u64>::new();
    for i in 0..(NODENUM - THRESHOLD) as u64 {
        let _ = non_responsives.insert(i);
    }
    let (peer_ids, mut generators) = setup_generators(&mut rng, non_responsives.clone());

    // The `messaging` function only ignores the non-initial proposals from a non-responsive node.
    // i.e. the Initialization phase will be completed and transits into Proposal.
    // With more non-responsive nodes, `finalize_contributing_phase` returns with Complaints of
    // non-contributors, and trigger the transition into Complaint phase. However, the Complaint
    // phase will be blocked as cannot collect more than threshold votes.
    // And the phase shall be blocked at Proposal.
    let mut proposals = Vec::new();

    // Trigger `finalize_contributing_phase` first, and exchange complaints
    peer_ids.iter().enumerate().for_each(|(index, _peer_id)| {
        if let Ok(proposal_vec) = generators[index].timed_phase_transition(&mut rng) {
            if !non_responsives.contains(&(index as u64)) {
                for proposal in proposal_vec {
                    proposals.push(proposal);
                }
            }
        }
    });
    messaging(
        &mut rng,
        &mut generators,
        &mut proposals,
        non_responsives.clone(),
    );

    // Then trigger `finalize_complaining_phase`, phase shall be blocked due to too many non-voters.
    peer_ids.iter().enumerate().for_each(|(index, peer_id)| {
        if let Err(err) = generators[index].timed_phase_transition(&mut rng) {
            assert_eq!(err, Error::TooManyNonVoters(non_responsives.clone()));
        } else {
            panic!("Node {:?} shall not progress anymore", peer_id);
        }
    });
    // List already returned within the above call to `finalize_complaining_phase`. So here it
    // returns an empty list.
    generators
        .iter()
        .for_each(|generator| assert!(generator.possible_blockers().is_empty()));
}

#[test]
fn threshold_signature() {
    let mut rng = rand::thread_rng();
    let (_, generators) = setup_generators(&mut rng, BTreeSet::new());

    // Compute the keys and threshold signature shares.
    let msg = "Hello from the group!";

    let outcome = generators[0]
        .generate_keys()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .1;

    let pub_key_set = outcome.public_key_set;

    let sig_shares: BTreeMap<_, _> = generators
        .iter()
        .enumerate()
        .map(|(idx, generator)| {
            assert!(generator.is_ready());
            let outcome = generator
                .generate_keys()
                .unwrap_or_else(|| {
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

    // Test threshold signature verification for a combination of signatures
    let sig_combinations = sig_shares.iter().combinations(THRESHOLD + 1);

    let deficient_sig_combinations = sig_shares.iter().combinations(THRESHOLD);

    for combination in deficient_sig_combinations.clone() {
        match pub_key_set.combine_signatures(combination) {
            Ok(_) => {
                panic!("Unexpected Success: Signatures cannot be aggregated with THRESHOLD shares")
            }
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
fn threshold_encrypt() {
    let mut rng = rand::thread_rng();
    let (_, generators) = setup_generators(&mut rng, BTreeSet::new());

    // Compute the keys and decryption shares.
    let msg = "Help for threshold encryption unit test!".as_bytes();

    let pub_key_set = generators[0]
        .generate_keys()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .1
        .public_key_set;
    let ciphertext = pub_key_set.public_key().encrypt(msg);

    let dec_shares: BTreeMap<_, _> = generators
        .iter()
        .enumerate()
        .map(|(idx, generator)| {
            assert!(generator.is_ready());
            let outcome = generator
                .generate_keys()
                .unwrap_or_else(|| {
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
            Ok(_) => panic!("Unexpected Success: Cannot decrypt by aggregating THRESHOLD shares"),
            Err(e) => assert_eq!(format!("{:?}", e), "NotEnoughShares".to_string()),
        }
    }
}

#[test]
fn network_churning() {
    let mut rng = rand::thread_rng();

    let initial_num = 3;
    let mut peer_ids = create_ids(initial_num);

    let mut naming_index = initial_num;

    while naming_index < 15 {
        if peer_ids.len() < NODENUM || rng.gen() {
            peer_ids.push(PeerId::new(NAMES[naming_index]));
            naming_index += 1;
        } else {
            let _ = peer_ids.remove(rng.gen_range(0, peer_ids.len()));
        }

        let threshold: usize = peer_ids.len() * 2 / 3;
        let mut generators = create_generators(&mut rng, BTreeSet::new(), &peer_ids, threshold);

        assert!(generators
            .iter_mut()
            .all(|key_gen| key_gen.generate_keys().is_some()));
    }
}
