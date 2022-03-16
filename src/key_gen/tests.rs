// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::dev_utils::{create_ids, PeerId};
use crate::key_gen::{message::Message, Error, KeyGen, MessageAndTarget};
use anyhow::{format_err, Result};
use bincode::serialize;
use blsttc::{PublicKeySet, SignatureShare};
use itertools::Itertools;
use rand::{Rng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use xor_name::XorName;

// Alter the configure of the number of nodes and the threshold.
const NODENUM: usize = 5;
const THRESHOLD: usize = 3;

fn setup_generators<R: RngCore>(
    mut rng: &mut R,
    non_responsives: BTreeSet<u64>,
) -> Result<(Vec<PeerId>, Vec<KeyGen>)> {
    // Generate individual ids.
    let peer_ids: Vec<PeerId> = create_ids(NODENUM);

    Ok((
        peer_ids.clone(),
        create_generators(&mut rng, non_responsives, &peer_ids, THRESHOLD)?,
    ))
}

fn create_generators<R: RngCore>(
    mut rng: &mut R,
    non_responsives: BTreeSet<u64>,
    peer_ids: &[PeerId],
    threshold: usize,
) -> Result<Vec<KeyGen>> {
    // Generate individual key pairs.
    let names: BTreeSet<XorName> = peer_ids.iter().map(|peer_id| peer_id.name()).collect();

    // Create the `KeyGen` instances
    let mut generators = Vec::new();
    let mut proposals = Vec::new();
    for peer_id in peer_ids.iter() {
        let key_gen = {
            let (key_gen, messaging) =
                match KeyGen::initialize(peer_id.name(), threshold, names.clone()) {
                    Ok(result) => result,
                    Err(err) => {
                        return Err(format_err!(
                            "Failed to initialize KeyGen of {:?} {:?}",
                            &peer_id,
                            err
                        ))
                    }
                };
            proposals.extend(messaging);
            key_gen
        };

        generators.push(key_gen);
    }

    messaging(&mut rng, &mut generators, &mut proposals, non_responsives);

    Ok(generators)
}

fn messaging<R: RngCore>(
    mut rng: &mut R,
    generators: &mut Vec<KeyGen>,
    proposals: &mut Vec<MessageAndTarget>,
    non_responsives: BTreeSet<u64>,
) {
    // Simulating the AE pattern
    let mut cached_msg = BTreeMap::<XorName, Message>::new();

    // Keep broadcasting the proposals among the generators till no more.
    // The proposal from non_responsive nodes shall be ignored.
    while !proposals.is_empty() {
        let proposals_local = std::mem::take(proposals);
        for (receiver, proposal) in &proposals_local {
            match proposal {
                Message::Initialization { .. } | Message::Proposal { .. } => {
                    let _ = cached_msg.insert(proposal.id(), proposal.clone());
                }
                _ => {}
            }
            for (index, generator) in generators.iter_mut().enumerate() {
                if receiver == &generator.our_id {
                    let messaging_vec = if let Ok(messaging_vec) =
                        generator.handle_message(&mut rng, proposal.clone())
                    {
                        messaging_vec
                    } else {
                        let mut messages: Vec<Message> = cached_msg.values().cloned().collect();
                        messages.push(proposal.clone());
                        let (messaging_vec, _unhandable) =
                            generator.handle_pre_session_messages(&mut rng, messages);
                        messaging_vec
                    };
                    if !non_responsives.contains(&(index as u64)) {
                        messaging_vec
                            .iter()
                            .for_each(|prop| proposals.push(prop.clone()));
                    }
                }
            }
        }
    }
}

#[test]
fn all_nodes_being_responsive() -> Result<()> {
    let mut rng = rand::thread_rng();
    let (_, mut generators) = setup_generators(&mut rng, BTreeSet::new())?;
    // With all participants responding properly, the key generating procedure shall be completed
    // automatically. As when there is no complaint, Justification phase will be triggered directly.
    assert!(generators
        .iter_mut()
        .all(|key_gen| key_gen.generate_keys().is_some()));
    Ok(())
}

#[test]
fn having_max_unresponsive_nodes_still_work() -> Result<()> {
    let mut rng = rand::thread_rng();
    let all_nodes: BTreeSet<_> = (0u64..NODENUM as u64).collect();
    let combinations_of_non_resp = all_nodes
        .iter()
        .cloned()
        .combinations(NODENUM - THRESHOLD - 1);

    for non_responsive in combinations_of_non_resp {
        let non_responsives: BTreeSet<u64> = non_responsive.iter().cloned().collect();
        let (peer_ids, mut generators) = setup_generators(&mut rng, non_responsives.clone())?;

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

        let responsive = all_nodes
            .difference(&non_responsives)
            .cloned()
            .collect_vec();

        let pub_key_set: PublicKeySet = generators[responsive[0] as usize]
            .generate_keys()
            .expect("Failed to generate `PublicKeySet` for node #0")
            .1
            .public_key_set;

        let msg = "Test message!";
        let mut sig_shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();

        for (index, key_gen) in generators.iter_mut().enumerate() {
            if !non_responsives.contains(&(index as u64)) {
                let outcome = if let Some(outcome) = key_gen.generate_keys() {
                    outcome.1
                } else {
                    return Err(format_err!(
                        "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                        index
                    ));
                };
                let sk = outcome.secret_key_share;
                let index = key_gen.our_index as usize;
                let pks = outcome.public_key_set;
                assert_eq!(pks, pub_key_set);
                let sig = sk.sign(msg);
                assert!(pks.public_key_share(index).verify(&sig, msg));
                let _ = sig_shares.insert(index, sig);

                non_responsives.iter().for_each(|idx| {
                    assert!(!key_gen.names().contains(&peer_ids[*idx as usize].name()))
                });
            } else {
                assert!(key_gen.generate_keys().is_none());
            };
        }

        let sig = match pub_key_set.combine_signatures(sig_shares.iter()) {
            Ok(sig) => sig,
            Err(e) => return Err(format_err!("Unexpected Error {:?}: Not able to generate Signature with THRESHOLD + 1 sig_shares", e)),
        };

        assert!(pub_key_set.public_key().verify(&sig, msg));
    }
    Ok(())
}

#[test]
fn having_min_unresponsive_nodes_cause_block() -> Result<()> {
    let mut rng = rand::thread_rng();
    let mut non_responsives = BTreeSet::<u64>::new();
    for i in 0..(NODENUM - THRESHOLD) as u64 {
        let _ = non_responsives.insert(i);
    }
    let (peer_ids, mut generators) = setup_generators(&mut rng, non_responsives.clone())?;

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
    for (index, peer_id) in peer_ids.iter().enumerate() {
        if let Err(err) = generators[index].timed_phase_transition(&mut rng) {
            assert_eq!(err, Error::TooManyNonVoters(non_responsives.clone()));
        } else {
            return Err(format_err!(
                "Node {:?}-{:?} shall not progress anymore",
                index,
                peer_id
            ));
        }
    }
    // List already returned within the above call to `finalize_complaining_phase`. So here it
    // returns an empty list.
    generators
        .iter()
        .for_each(|generator| assert!(generator.possible_blockers().is_empty()));
    Ok(())
}

#[test]
fn threshold_signature() -> Result<()> {
    let mut rng = rand::thread_rng();
    let (_, generators) = setup_generators(&mut rng, BTreeSet::new())?;

    // Compute the keys and threshold signature shares.
    let msg = "Hello from the group!";

    let pub_key_set = generators[0]
        .generate_keys()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .1
        .public_key_set;

    let mut sig_shares = BTreeMap::new();
    for (idx, generator) in generators.iter().enumerate() {
        assert!(generator.is_ready());
        let outcome = if let Some(outcome) = generator.generate_keys() {
            outcome.1
        } else {
            return Err(format_err!(
                "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                idx
            ));
        };
        let sk = outcome.secret_key_share;
        let pks = outcome.public_key_set;
        assert_eq!(pks, pub_key_set);
        let sig = sk.sign(msg);
        assert!(pks.public_key_share(idx).verify(&sig, msg));
        let _ = sig_shares.insert(idx, sig);
    }

    // Test threshold signature verification for a combination of signatures
    let sig_combinations = sig_shares.iter().combinations(THRESHOLD + 1);

    let deficient_sig_combinations = sig_shares.iter().combinations(THRESHOLD);

    for combination in deficient_sig_combinations.clone() {
        match pub_key_set.combine_signatures(combination) {
            Ok(_) => {
                return Err(format_err!(
                    "Unexpected Success: Signatures cannot be aggregated with THRESHOLD shares"
                ));
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
        let sig_ser = if let Ok(sig_ser) = serialize(&sig) {
            sig_ser
        } else {
            return Err(format_err!("cannot serialize signature 1"));
        };
        let sig2 = pub_key_set
            .combine_signatures(signature_shares[1].clone())
            .expect("signature shares match");
        let sig2_ser = if let Ok(sig_ser) = serialize(&sig2) {
            sig_ser
        } else {
            return Err(format_err!("cannot serialize signature 2"));
        };
        assert_eq!(sig_ser, sig2_ser);
    }
    Ok(())
}

#[test]
fn threshold_encrypt() -> Result<()> {
    let mut rng = rand::thread_rng();
    let (_, generators) = setup_generators(&mut rng, BTreeSet::new())?;

    // Compute the keys and decryption shares.
    let msg = "Help for threshold encryption unit test!".as_bytes();

    let pub_key_set = generators[0]
        .generate_keys()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .1
        .public_key_set;
    let ciphertext = pub_key_set.public_key().encrypt(msg);

    let mut dec_shares = BTreeMap::new();

    for (idx, generator) in generators.iter().enumerate() {
        assert!(generator.is_ready());
        let outcome = if let Some(outcome) = generator.generate_keys() {
            outcome.1
        } else {
            return Err(format_err!(
                "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                idx
            ));
        };
        let sk = outcome.secret_key_share;
        let pks = outcome.public_key_set;
        assert_eq!(pks, pub_key_set);
        let dec_share = if let Some(dec_share) = sk.decrypt_share(&ciphertext) {
            dec_share
        } else {
            return Err(format_err!("Cannot create a decrypt share."));
        };
        assert!(pks
            .public_key_share(idx)
            .verify_decryption_share(&dec_share, &ciphertext));

        let _ = dec_shares.insert(idx, dec_share);
    }
    // Test threshold encryption verification for a combination of shares - should pass as there
    // are THRESHOLD + 1 shares aggregated in each combination
    let dec_share_combinations = dec_shares.iter().combinations(THRESHOLD + 1);
    for dec_share in dec_share_combinations {
        let decrypted = if let Ok(decrypted) = pub_key_set.decrypt(dec_share, &ciphertext) {
            decrypted
        } else {
            return Err(format_err!("Cannot verify a decrypt share."));
        };
        assert_eq!(msg, decrypted.as_slice());
    }

    // Test threshold decryption for a combination of shares - shouldn't decrypt as there
    // are THRESHOLD shares in each combination which are not enough to aggregate
    let deficient_dec_share_combinations = dec_shares.iter().combinations(THRESHOLD);
    for deficient_dec_share in deficient_dec_share_combinations {
        match pub_key_set.decrypt(deficient_dec_share, &ciphertext) {
            Ok(_) => {
                return Err(format_err!(
                    "Unexpected Success: Cannot decrypt by aggregating THRESHOLD shares"
                ))
            }
            Err(e) => assert_eq!(format!("{:?}", e), "NotEnoughShares".to_string()),
        }
    }
    Ok(())
}

#[test]
fn network_churning() -> Result<()> {
    let mut rng = rand::thread_rng();

    let initial_num = 3;
    let mut peer_ids = create_ids(initial_num);

    let mut naming_index = initial_num;

    while naming_index < 15 {
        if peer_ids.len() < NODENUM || rng.gen() {
            peer_ids.push(PeerId::new());
            naming_index += 1;
        } else {
            let _ = peer_ids.remove(rng.gen_range(0..peer_ids.len()));
        }

        let threshold: usize = peer_ids.len() * 2 / 3;
        let mut generators = create_generators(&mut rng, BTreeSet::new(), &peer_ids, threshold)?;

        assert!(generators
            .iter_mut()
            .all(|key_gen| key_gen.generate_keys().is_some()));
    }
    Ok(())
}
