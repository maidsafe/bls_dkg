// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::dev_utils::{create_ids, new_common_rng, PeerId, RngChoice};
use crate::id::SecretId;
use crate::key_gen::{message::DkgMessage, DkgPhases, KeyGen};
use maidsafe_utilities::{serialisation::serialise, SeededRng};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

// Alter the seed here to reproduce failures.
static SEED: RngChoice = RngChoice::SeededRandom;

// Alter the configure of the number of nodes and the threshold.
const NODENUM: usize = 7;
const THRESHOLD: usize = 5;

fn setup_generators(
    mut rng: &mut dyn Rng,
    dkg_phase: DkgPhases,
    non_responsive: Option<usize>,
) -> (Vec<PeerId>, Vec<KeyGen<PeerId>>) {
    // Generate individual ids and key pairs.
    let peer_ids: Vec<PeerId> = create_ids(NODENUM);
    let pub_keys: BTreeSet<PeerId> = peer_ids.iter().cloned().collect();

    // Create the `KeyGen` instances
    let mut generators = Vec::new();
    let mut proposals = Vec::new();
    peer_ids.iter().enumerate().for_each(|(index, peer_id)| {
        let mut key_gen = if dkg_phase == DkgPhases::Initialization {
            let (key_gen, proposal) =
                KeyGen::<PeerId>::initialize(&peer_id.sec_key(), THRESHOLD, pub_keys.clone())
                    .unwrap_or_else(|_err| panic!("Failed to initial KeyGen of {:?}", &peer_id));
            proposals.push(proposal);
            key_gen
        } else {
            KeyGen::<PeerId>::initialize_for_test(
                peer_id.public_id().clone(),
                index as u64,
                pub_keys.clone(),
                THRESHOLD,
                dkg_phase,
            )
        };

        // Calling `finalize_complaining_phase` to trigger the key_gen instance transit into
        // Justification phase and send out the initial proposal.
        if dkg_phase == DkgPhases::Complaining {
            let proposal = key_gen
                .finalize_complaining_phase(&peer_id.sec_key(), &mut rng)
                .unwrap_or_else(|_err| {
                    panic!("Failed to complete complaint stage of {:?}", &peer_id)
                });
            proposals.push(proposal);
        }
        generators.push(key_gen);
    });

    messaging(
        &mut rng,
        &peer_ids,
        &mut generators,
        &mut proposals,
        non_responsive,
    );

    (peer_ids, generators)
}

fn messaging(
    mut rng: &mut dyn Rng,
    peer_ids: &[PeerId],
    generators: &mut Vec<KeyGen<PeerId>>,
    proposals: &mut Vec<DkgMessage<PeerId>>,
    non_responsive: Option<usize>,
) {
    // Keep broadcasting the proposals among the generators till no more.
    // The proposal from non_responsive node shall be ignored.
    while !proposals.is_empty() {
        let proposals_local = std::mem::replace(proposals, Vec::new());
        for proposal in &proposals_local {
            for (index, generator) in generators.iter_mut().enumerate() {
                if let Ok(Some(proposal_vec)) =
                    generator.handle_message(peer_ids[index].sec_key(), &mut rng, proposal.clone())
                {
                    if Some(index) != non_responsive {
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
    let mut rng = new_common_rng(SEED);
    let (_, mut generators) = setup_generators(&mut rng, DkgPhases::Initialization, None);
    // With all participants responding properly, the key generating procedure shall be completed
    // automatically. As when there is no complaint, Justification phase will be triggered directly.
    assert!(generators
        .iter_mut()
        .all(|key_gen| key_gen.generate_keys().is_ok()));
}

#[test]
fn having_one_non_responsive_node() {
    let mut rng = new_common_rng(SEED);
    let non_responsive = Some(0);
    let (peer_ids, mut generators) =
        setup_generators(&mut rng, DkgPhases::Initialization, non_responsive);

    let mut proposals = Vec::new();
    // With one non_responsive node, Contribution phase cannot be completed automatically. This
    // requires finalize_contributing_phase to be called externally to complete the procedure.
    peer_ids.iter().enumerate().for_each(|(index, peer_id)| {
        if let Ok(Some(proposal_vec)) =
            generators[index].finalize_contributing_phase(&peer_id.sec_key(), &mut rng)
        {
            if Some(index) != non_responsive {
                for proposal in proposal_vec {
                    proposals.push(proposal);
                }
            }
        }
    });
    // Continue the procedure with messaging.
    messaging(
        &mut rng,
        &peer_ids,
        &mut generators,
        &mut proposals,
        non_responsive,
    );

    assert!(proposals.is_empty());

    // With one non_responsive node, all participants will transit into Complaint phase. This
    // requires finalize_complaining_phase to be called externally to complete the procedure.
    peer_ids.iter().enumerate().for_each(|(index, peer_id)| {
        if Some(index) != non_responsive {
            proposals.push(
                generators[index]
                    .finalize_complaining_phase(&peer_id.sec_key(), &mut rng)
                    .unwrap(),
            );
        }
    });
    // Continue the procedure with messaging.
    messaging(
        &mut rng,
        &peer_ids,
        &mut generators,
        &mut proposals,
        non_responsive,
    );

    generators
        .iter_mut()
        .enumerate()
        .for_each(|(index, key_gen)| {
            if Some(index) != non_responsive {
                assert!(key_gen.generate_keys().is_ok());
                assert!(!key_gen
                    .pub_keys()
                    .contains(&peer_ids[non_responsive.unwrap()]));
            } else {
                assert!(key_gen.generate_keys().is_err());
            }
        });
}

#[test]
fn threshold_signature() {
    let mut rng = new_common_rng(SEED);
    let (_, mut generators) = setup_generators(&mut rng, DkgPhases::Complaining, None);

    // Compute the keys and threshold signature shares.
    let msg = "Help I'm trapped in a unit test factory";
    let pub_key_set = generators[0]
        .generate_keys()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .1
        .public_key_set;
    let sig_shares: BTreeMap<_, _> = generators
        .iter()
        .enumerate()
        .map(|(idx, generator)| {
            assert!(generator.is_ready());
            let dkg_result = generator
                .generate_keys()
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                        idx
                    )
                })
                .1;
            let sk = dkg_result.secret_key_share;
            let pks = dkg_result.public_key_set;
            assert_eq!(pks, pub_key_set);
            let sig = sk.sign(msg);
            assert!(pks.public_key_share(idx).verify(&sig, msg));
            (idx, sig)
        })
        .collect();

    // Test a threshold signature
    let sig = pub_key_set
        .combine_signatures(sig_shares.iter().take(THRESHOLD + 1))
        .expect("signature shares match");
    assert!(pub_key_set.public_key().verify(&sig, msg));

    // Test a second threshold signature
    let sig2_start_idx = rng.gen_range(1, std::cmp::max(2, sig_shares.len()));
    let sig2 = pub_key_set
        .combine_signatures(
            sig_shares
                .iter()
                .cycle()
                .skip(sig2_start_idx)
                .take(THRESHOLD + 1),
        )
        .expect("signature shares match");
    assert!(pub_key_set.public_key().verify(&sig2, msg));

    // Test signature aggregated from different share are the same
    let sig_ser = unwrap!(serialise(&sig));
    let sig2_ser = unwrap!(serialise(&sig2));
    assert_eq!(sig_ser, sig2_ser);
}

#[test]
fn threshold_encrypt() {
    let mut rng = new_common_rng(SEED);
    let (_, mut generators) = setup_generators(&mut rng, DkgPhases::Complaining, None);

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
            let dkg_result = generator
                .generate_keys()
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                        idx
                    )
                })
                .1;
            let sk = dkg_result.secret_key_share;
            let pks = dkg_result.public_key_set;
            assert_eq!(pks, pub_key_set);

            let dec_share = sk.decrypt_share(&ciphertext).unwrap();

            assert!(pks
                .public_key_share(idx)
                .verify_decryption_share(&dec_share, &ciphertext));

            (idx, dec_share)
        })
        .collect();

    let decrypted = pub_key_set.decrypt(&dec_shares, &ciphertext).unwrap();
    assert_eq!(msg, decrypted.as_slice());
}
