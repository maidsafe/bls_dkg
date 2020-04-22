// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod encryptor;
pub mod message;
pub mod outcome;
mod rng_adapter;

#[cfg(test)]
mod tests;

use crate::id::{PublicId, SecretId};
use bincode::{self, deserialize, serialize};
use encryptor::Encryptor;
use err_derive;
use message::Message;
use outcome::Outcome;
use rand::{self, RngCore};
use serde_derive::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use threshold_crypto::pairing::{CurveAffine, Field};
use threshold_crypto::{
    poly::{BivarCommitment, BivarPoly, Poly},
    serde_impl::FieldWrap,
    Fr, G1Affine, SecretKeyShare,
};

/// A local error while handling a message, that was not caused by that message being invalid.
#[derive(Clone, Eq, err_derive::Error, PartialEq, Debug)]
pub enum Error {
    /// Unknown error.
    #[error(display = "Unknown")]
    Unknown,
    /// Unknown sender.
    #[error(display = "Unknown sender")]
    UnknownSender,
    /// Failed to serialize message.
    #[error(display = "Serialization error: {}", _0)]
    Serialization(String),
    /// Failed to encrypt message.
    #[error(display = "Encryption error")]
    Encryption,
    /// Failed to finalize Complaint phase due to too many non-voters.
    #[error(display = "Too many non-voters error")]
    TooManyNonVoters(BTreeSet<u64>),
    /// Unexpected phase.
    #[error(display = "Unexpected phase")]
    UnexpectedPhase { expected: Phase, actual: Phase },
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(err: Box<bincode::ErrorKind>) -> Error {
        Error::Serialization(format!("{:?}", err))
    }
}

/// A contribution by a node for the key generation. It must to be sent to all participating
/// nodes and handled by all of them, it contains `receiver_index, serialised row for the receiver,
/// encrypted rows from the sender`.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Part(u64, BivarCommitment, Vec<u8>, Vec<Vec<u8>>);

impl Debug for Part {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Part")
            .field(&format!("<receiver {}>", &self.0))
            .field(&format!("<degree {}>", self.1.degree()))
            .field(&format!("<{} rows>", self.3.len()))
            .finish()
    }
}

/// A confirmation that we have received and verified a validator's part. It must be sent to
/// all participating nodes and handled by all of them, including ourselves.
///
/// The message is only produced after we verified our row against the commitment in the `Part`.
/// For each node, it contains `proposal_index, receiver_index, serialised value for the receiver,
/// encrypted values from the sender`.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Commitment(u64, u64, Vec<u8>, Vec<Vec<u8>>);

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Commitment")
            .field(&format!("<proposer {}>", &self.0))
            .field(&format!("<receiver {}>", &self.1))
            .field(&format!("<{} values>", self.3.len()))
            .finish()
    }
}

/// The information needed to track a single proposer's secret sharing process.
#[derive(Debug, PartialEq, Eq)]
struct ProposalState {
    /// The proposer's commitment.
    commitment: BivarCommitment,
    /// The verified values we received from `Commitment` messages.
    values: BTreeMap<u64, Fr>,
    /// The encrypted values received from the proposor.
    enc_values: Vec<Vec<u8>>,
    /// The nodes which have committed.
    commitments: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commitment: BivarCommitment) -> ProposalState {
        ProposalState {
            commitment,
            values: BTreeMap::new(),
            enc_values: Vec::new(),
            commitments: BTreeSet::new(),
        }
    }

    fn is_complete(&self, threshold: usize) -> bool {
        self.commitments.len() > threshold
    }
}

impl<'a> serde::Deserialize<'a> for ProposalState {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let (commitment, values, enc_values, commitments) =
            serde::Deserialize::deserialize(deserializer)?;
        let values: Vec<(u64, FieldWrap<Fr>)> = values;
        Ok(Self {
            commitment,
            values: values
                .into_iter()
                .map(|(index, fr)| (index, fr.0))
                .collect(),
            enc_values,
            commitments,
        })
    }
}

/// The outcome of handling and verifying a `Part` message.
pub enum PartOutcome {
    /// The message was valid: the part of it that was encrypted to us matched the public
    /// commitment, so we can multicast an `Commitment` message for it. If we have already handled the
    /// same `Part` before, this contains `None` instead.
    Valid(Option<Commitment>),
    /// The message was invalid: We now know that the proposer is faulty.
    Invalid(PartFault),
}

/// The outcome of handling and verifying a `Commitment` message.
pub enum CommitmentOutcome {
    /// The message was valid.
    Valid,
    /// The message was invalid: The sender is faulty.
    Invalid(CommitmentFault),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum Phase {
    Initialization,
    Contribution,
    Complaining,
    Justification,
    Commitment,
    Finalization,
}

#[derive(Default)]
struct InitializationAccumulator<P: PublicId> {
    senders: BTreeSet<u64>,
    initializations: BTreeMap<(usize, usize, BTreeSet<P>), usize>,
}

impl<P: PublicId> InitializationAccumulator<P> {
    fn new() -> InitializationAccumulator<P> {
        InitializationAccumulator {
            senders: BTreeSet::new(),
            initializations: BTreeMap::new(),
        }
    }

    fn add_initialization(
        &mut self,
        // Following the `m of n` terminology, here m is the threshold and n is the total number.
        m: usize,
        n: usize,
        sender: u64,
        member_list: BTreeSet<P>,
    ) -> Option<(usize, usize, BTreeSet<P>)> {
        if !self.senders.insert(sender) {
            return None;
        }

        let paras = (m, n, member_list);
        if let Some(value) = self.initializations.get_mut(&paras) {
            *value += 1;
            if *value >= m {
                return Some(paras);
            }
        } else {
            let _ = self.initializations.insert(paras, 1);
        }
        None
    }
}

#[derive(Default)]
struct ContributionAccumulator<P: PublicId> {
    pub_keys: BTreeSet<P>,
    // Indexed by (id, index), value is the `part`.
    contributions: BTreeMap<(P, u64), Part>,
}

impl<P: PublicId> ContributionAccumulator<P> {
    fn new(pub_keys: BTreeSet<P>) -> ContributionAccumulator<P> {
        ContributionAccumulator {
            pub_keys,
            contributions: BTreeMap::new(),
        }
    }

    // returns `true` when received contributions from all expected senders.
    fn add_contribution(&mut self, sender_id: P, sender_index: u64, part: Part) -> bool {
        if !self.pub_keys.contains(&sender_id) {
            return false;
        }
        let _ = self.contributions.insert((sender_id, sender_index), part);
        self.contributions.len() == self.pub_keys.len()
    }

    fn non_contributors(&self) -> BTreeSet<P> {
        let mut result = self.pub_keys.clone();
        self.contributions.keys().for_each(|(pk, _)| {
            let _ = result.remove(pk);
        });
        result
    }
}

#[derive(Default)]
struct ComplaintsAccumulator<P: PublicId> {
    pub_keys: BTreeSet<P>,
    threshold: usize,
    // Indexed by complaining targets.
    complaints: BTreeMap<P, BTreeSet<P>>,
}

impl<P: PublicId> ComplaintsAccumulator<P> {
    fn new(pub_keys: BTreeSet<P>, threshold: usize) -> ComplaintsAccumulator<P> {
        ComplaintsAccumulator {
            pub_keys,
            threshold,
            complaints: BTreeMap::new(),
        }
    }

    // TODO: accusation shall be validated.
    fn add_complaint(&mut self, sender_id: P, target_id: P, _msg: Vec<u8>) {
        if !self.pub_keys.contains(&sender_id) || !self.pub_keys.contains(&target_id) {
            return;
        }

        match self.complaints.entry(target_id.clone()) {
            Entry::Occupied(mut entry) => {
                let _ = entry.get_mut().insert(sender_id);
            }
            Entry::Vacant(entry) => {
                let mut targets = BTreeSet::new();
                let _ = targets.insert(target_id);
                let _ = entry.insert(targets);
            }
        }
    }

    // Returns the invalid peers that quorumn members complained against, together with the
    // non-contributors. Both shall be considered as invalid participants.
    fn finalize_complaining_phase(&self) -> BTreeSet<P> {
        let mut invalid_peers = BTreeSet::new();

        // Counts for how many times a member missed complaining against others validly.
        // If missed too many times, such member shall be considered as invalid directly.
        let mut counts: BTreeMap<P, usize> = BTreeMap::new();

        for (target_id, accusers) in self.complaints.iter() {
            if accusers.len() > self.pub_keys.len() - self.threshold {
                let _ = invalid_peers.insert(target_id.clone());
                for peer in self.pub_keys.iter() {
                    if !accusers.contains(peer) {
                        *counts.entry(peer.clone()).or_insert(0usize) += 1;
                    }
                }
            }
        }
        for (peer, times) in counts {
            if times > self.pub_keys.len() / 2 {
                let _ = invalid_peers.insert(peer);
            }
        }

        invalid_peers
    }
}

/// An algorithm for dealerless distributed key generation.
///
/// This is trying to follow the protocol as suggested at
/// https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md#distributed-key-generation-dkg-protocol
///
/// A normal usage flow will be:
///   a, call `initialize` first to generate an instance.
///   b, multicasting the return `Message` to all participants.
///   c, call `handle_message` function to handle the incoming `Message` and multicasting the
///      resulted `Message` (if has) to all participants.
///   d, call `finalize_complaining_phase` to complete the complaining phase. (This separate call may need to
///      depend on a separate timer & checker against the key generator's current status)
///   e, repeat step c when there is incoming `Message`.
///   f, call `generate_keys` to get the public-key set and secret-key share, if the procedure finalized.
pub struct KeyGen<S: SecretId> {
    /// Our node ID.
    our_id: S::PublicId,
    /// Our node index.
    our_index: u64,
    /// The public keys of all nodes, by node ID.
    pub_keys: BTreeSet<S::PublicId>,
    /// Carry out encryption work during the DKG process.
    encryptor: Encryptor<S::PublicId>,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
    /// Current DKG phase.
    phase: Phase,
    /// Accumulates initializations.
    initalization_accumulator: InitializationAccumulator<S::PublicId>,
    /// Accumulates contributions.
    contribution_accumulator: ContributionAccumulator<S::PublicId>,
    /// Accumulates complaints.
    complaints_accumulator: ComplaintsAccumulator<S::PublicId>,
}

impl<S: SecretId> KeyGen<S> {
    /// Creates a new `KeyGen` instance, together with the `Initial` message that should be
    /// multicast to all nodes.
    pub fn initialize(
        sec_key: &S,
        threshold: usize,
        pub_keys: BTreeSet<S::PublicId>,
    ) -> Result<(KeyGen<S>, Message<S::PublicId>), Error> {
        if pub_keys.len() < threshold {
            return Err(Error::Unknown);
        }
        let our_id = sec_key.public_id().clone();
        let our_index = if let Some(index) = pub_keys.iter().position(|id| *id == our_id) {
            index as u64
        } else {
            return Err(Error::Unknown);
        };

        let key_gen = KeyGen::<S> {
            our_id,
            our_index,
            pub_keys: pub_keys.clone(),
            encryptor: Encryptor::new(&pub_keys),
            parts: BTreeMap::new(),
            threshold,
            phase: Phase::Initialization,
            initalization_accumulator: InitializationAccumulator::new(),
            contribution_accumulator: ContributionAccumulator::new(pub_keys.clone()),
            complaints_accumulator: ComplaintsAccumulator::new(pub_keys.clone(), threshold),
        };

        Ok((
            key_gen,
            Message::Initialization {
                key_gen_id: our_index,
                m: threshold,
                n: pub_keys.len(),
                member_list: pub_keys,
            },
        ))
    }

    /// Dispatching an incoming dkg message.
    pub fn handle_message<R: RngCore>(
        &mut self,
        rng: &mut R,
        msg: Message<S::PublicId>,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        match msg {
            Message::Initialization {
                key_gen_id,
                m,
                n,
                member_list,
            } => self.handle_initialization(rng, m, n, key_gen_id, member_list),
            Message::Contribution { key_gen_id, part } => {
                self.handle_contribution(rng, key_gen_id, part)
            }
            Message::Complaint {
                key_gen_id,
                target,
                msg,
            } => self.handle_complaint(key_gen_id, target, msg),
            Message::Justification { key_gen_id, part } => {
                self.handle_justification(key_gen_id, part)
            }
            Message::Commitment {
                key_gen_id,
                commitment,
            } => {
                if let Err(err) = self.handle_commitment(key_gen_id, commitment) {
                    Err(err)
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    // Handles an incoming initialize message. Creates the `Contribution` message once quorumn
    // agreement reached, and the message should be multicast to all nodes.
    fn handle_initialization<R: RngCore>(
        &mut self,
        rng: &mut R,
        m: usize,
        n: usize,
        sender: u64,
        member_list: BTreeSet<S::PublicId>,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        if self.phase != Phase::Initialization {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Initialization,
                actual: self.phase,
            });
        }

        if let Some((m, _n, member_list)) =
            self.initalization_accumulator
                .add_initialization(m, n, sender, member_list)
        {
            self.threshold = m;
            self.pub_keys = member_list;
            self.phase = Phase::Contribution;

            let mut rng = rng_adapter::RngAdapter(&mut *rng);
            let our_part = BivarPoly::random(self.threshold, &mut rng);
            let commitment = our_part.commitment();
            let encrypt = |(i, pk): (usize, &S::PublicId)| {
                let row = our_part.row(i + 1);
                self.encryptor.encrypt(pk, &serialize(&row)?)
            };
            let rows = self
                .pub_keys
                .iter()
                .enumerate()
                .map(encrypt)
                .collect::<Result<Vec<_>, Error>>()?;
            let result = self
                .pub_keys
                .iter()
                .enumerate()
                .map(|(idx, _pk)| {
                    let ser_row = serialize(&our_part.row(idx + 1))?;
                    Ok(Message::Contribution {
                        key_gen_id: self.our_index,
                        part: Part(idx as u64, commitment.clone(), ser_row, rows.clone()),
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            return Ok(result);
        }
        Ok(Vec::new())
    }

    // Handles a `Contribution` message.
    // If it is invalid, sends a `Complaint` message targeting the sender to be broadcast.
    // If all contributed, returns a `Commitment` message to be broadcast.
    fn handle_contribution<R: RngCore>(
        &mut self,
        rng: &mut R,
        sender_index: u64,
        part: Part,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        if self.phase != Phase::Contribution {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Contribution,
                actual: self.phase,
            });
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;

        if self
            .contribution_accumulator
            .add_contribution(sender_id, sender_index, part)
        {
            self.finalize_contributing_phase(rng)
        } else {
            Ok(Vec::new())
        }
    }

    // TODO: So far this function has to be called externally to indicates a completion of the
    //       contribution phase. That is, the owner of the key_gen instance has to wait for a fixed
    //       interval, say an expected timer of 5 minutes, to allow the messages to be exchanged.
    //       May need to be further verified whether there is a better approach.
    pub fn timed_phase_transition<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        match self.phase {
            Phase::Contribution => self.finalize_contributing_phase(rng),
            Phase::Complaining => self.finalize_complaining_phase(rng),
            Phase::Initialization => Err(Error::UnexpectedPhase {
                expected: Phase::Contribution,
                actual: self.phase,
            }),
            Phase::Commitment | Phase::Justification => Err(Error::UnexpectedPhase {
                expected: Phase::Complaining,
                actual: self.phase,
            }),

            Phase::Finalization => Ok(Vec::new()),
        }
    }

    fn finalize_contributing_phase<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        self.phase = Phase::Complaining;

        let mut msgs = Vec::new();
        let mut contributors = BTreeSet::new();
        for ((sender_id, sender_index), part) in self.contribution_accumulator.contributions.clone()
        {
            match self.handle_part_or_fault(sender_index, part.clone()) {
                Ok(Some(_row)) => {}
                Ok(None) => {}
                Err(_fault) => {
                    let msg = Message::Contribution::<S::PublicId> {
                        key_gen_id: sender_index,
                        part,
                    };
                    let invalid_contribute = serialize(&msg)?;
                    msgs.push(Message::Complaint {
                        key_gen_id: self.our_index,
                        target: sender_index,
                        msg: invalid_contribute,
                    });
                }
            }
            let _ = contributors.insert(sender_id);
        }

        for expected in self.pub_keys.iter() {
            if !contributors.contains(expected) {
                let target = self.node_index(expected).ok_or(Error::Unknown)?;
                msgs.push(Message::Complaint {
                    key_gen_id: self.our_index,
                    target,
                    msg: b"Not contributed".to_vec(),
                });
            }
        }

        // In case of no complaints, calling finalize_complaining_phase to transit into
        // `Justification` phase.
        if msgs.is_empty() {
            self.finalize_complaining_phase(rng)
        } else {
            Ok(msgs)
        }
    }

    // Handles a `Complaint` message.
    fn handle_complaint(
        &mut self,
        sender_index: u64,
        target_index: u64,
        invalid_msg: Vec<u8>,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        if self.phase != Phase::Complaining {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Complaining,
                actual: self.phase,
            });
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;
        let target_id = self
            .node_id_from_index(target_index)
            .ok_or(Error::Unknown)?;

        self.complaints_accumulator
            .add_complaint(sender_id, target_id, invalid_msg);
        Ok(Vec::new())
    }

    fn finalize_complaining_phase<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        let failings = self.complaints_accumulator.finalize_complaining_phase();
        if failings.len() >= self.pub_keys.len() - self.threshold {
            let mut result = BTreeSet::new();
            failings.iter().for_each(|pk| {
                if let Some(index) = self.node_index(pk) {
                    let _ = result.insert(index);
                }
            });
            return Err(Error::TooManyNonVoters(result));
        }

        if !failings.is_empty() {
            for failing in failings.iter() {
                let _ = self.pub_keys.remove(failing);
            }
            self.our_index = self.node_index(&self.our_id).ok_or(Error::Unknown)?;
        }

        self.phase = Phase::Justification;
        self.parts = BTreeMap::new();

        let mut rng = rng_adapter::RngAdapter(&mut *rng);
        let our_part = BivarPoly::random(self.threshold, &mut rng);
        let justify = our_part.commitment();
        let encrypt = |(i, pk): (usize, &S::PublicId)| {
            let row = our_part.row(i + 1);
            self.encryptor.encrypt(pk, &serialize(&row)?)
        };
        let rows = self
            .pub_keys
            .iter()
            .enumerate()
            .map(encrypt)
            .collect::<Result<Vec<_>, Error>>()?;

        let result = self
            .pub_keys
            .iter()
            .enumerate()
            .map(|(idx, _pk)| {
                let ser_row = serialize(&our_part.row(idx + 1))?;
                Ok(Message::Justification {
                    key_gen_id: self.our_index,
                    part: Part(idx as u64, justify.clone(), ser_row, rows.clone()),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(result)
    }

    // Handles a `Justification` message.
    fn handle_justification(
        &mut self,
        sender_index: u64,
        part: Part,
    ) -> Result<Vec<Message<S::PublicId>>, Error> {
        if self.phase != Phase::Justification {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Justification,
                actual: self.phase,
            });
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;
        let row = match self.handle_part_or_fault(sender_index, part) {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(Vec::new()),
            Err(_fault) => {
                // In case of a failure, the sender shall be removed directly.
                let _ = self.pub_keys.remove(&sender_id);
                return Ok(Vec::new());
            }
        };
        // The row is valid. Encrypt one value for each node and broadcast `Commitment`.
        let mut values = Vec::new();
        let mut enc_values = Vec::new();
        for (index, pk) in self.pub_keys.iter().enumerate() {
            let val = row.evaluate(index + 1);
            let ser_val = serialize(&FieldWrap(val))?;
            enc_values.push(self.encryptor.encrypt(pk, &ser_val)?);
            values.push(ser_val);
        }

        let result = self
            .pub_keys
            .iter()
            .enumerate()
            .map(|(idx, _pk)| Message::Commitment {
                key_gen_id: self.our_index,
                commitment: Commitment(
                    sender_index,
                    idx as u64,
                    values[idx].clone(),
                    enc_values.clone(),
                ),
            })
            .collect();

        if self.parts.len() == self.pub_keys.len() {
            self.phase = Phase::Commitment;
        }

        Ok(result)
    }

    // Handles a `Commitment` message.
    fn handle_commitment(
        &mut self,
        sender_index: u64,
        commitment: Commitment,
    ) -> Result<CommitmentOutcome, Error> {
        if self.phase != Phase::Commitment {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Commitment,
                actual: self.phase,
            });
        }

        Ok(
            match self.handle_commitment_or_fault(sender_index, commitment) {
                Ok(()) => {
                    if self.is_ready() {
                        self.phase = Phase::Finalization;
                    }
                    CommitmentOutcome::Valid
                }
                Err(fault) => CommitmentOutcome::Invalid(fault),
            },
        )
    }

    /// Returns the index of the node, or `None` if it is unknown.
    fn node_index(&self, node_id: &S::PublicId) -> Option<u64> {
        self.pub_keys
            .iter()
            .position(|id| id == node_id)
            .map(|index| index as u64)
    }

    /// Returns the id of the index, or `None` if it is unknown.
    fn node_id_from_index(&self, node_index: u64) -> Option<S::PublicId> {
        for (i, pk) in self.pub_keys.iter().enumerate() {
            if i == node_index as usize {
                return Some(pk.clone());
            }
        }
        None
    }

    /// Returns the number of complete parts. If this is at least `threshold + 1`, the keys can
    /// be generated, but it is possible to wait for more to increase security.
    fn complete_parts_count(&self) -> usize {
        self.parts
            .values()
            .filter(|part| part.is_complete(self.threshold))
            .count()
    }

    /// Returns `true` if enough parts are complete to safely generate the new key.
    fn is_ready(&self) -> bool {
        self.complete_parts_count() >= self.threshold
    }

    /// Returns the new secret key share and the public key set.
    pub fn generate_keys(&self) -> Option<(BTreeSet<S::PublicId>, Outcome)> {
        if self.phase != Phase::Finalization {
            return None;
        }

        let mut pk_commitment = Poly::zero().commitment();
        let mut sk_val = Fr::zero();
        let is_complete = |part: &&ProposalState| part.is_complete(self.threshold);
        for part in self.parts.values().filter(is_complete) {
            pk_commitment += part.commitment.row(0);
            let row = Poly::interpolate(part.values.iter().take(self.threshold + 1));
            sk_val.add_assign(&row.evaluate(0));
        }
        let sk = SecretKeyShare::from_mut(&mut sk_val);
        Some((
            self.pub_keys.clone(),
            Outcome::new(pk_commitment.into(), sk),
        ))
    }

    /// This function shall be called when the DKG procedure not reach Finalization phase and before
    /// discarding the instace. It returns potential invalid peers that causing the blocking, if
    /// any and provable.
    pub fn possible_blockers(&self) -> BTreeSet<S::PublicId> {
        let mut result = BTreeSet::new();
        match self.phase {
            Phase::Initialization => {
                for (index, pk) in self.pub_keys.iter().enumerate() {
                    if !self
                        .initalization_accumulator
                        .senders
                        .contains(&(index as u64))
                    {
                        let _ = result.insert(pk.clone());
                    }
                }
            }
            Phase::Contribution => result = self.contribution_accumulator.non_contributors(),
            Phase::Complaining => {
                // Non-voters shall already be returned within the error of the
                // finalize_complaint_phase function call.
            }
            Phase::Justification | Phase::Commitment => {
                // As there was Complaint phase being complated, it is exepcted all nodes involved
                // in these two phases. Hence here a strict rule is undertaken that: any missing
                // vote will be considered as a potential non-voter.
                for part in self.parts.values() {
                    for (index, pk) in self.pub_keys.iter().enumerate() {
                        if !part.commitments.contains(&(index as u64)) {
                            let _ = result.insert(pk.clone());
                        }
                    }
                }
            }
            Phase::Finalization => {
                // Not blocking
            }
        }
        result
    }

    /// Handles a `Part`, returns a `PartFault` if it is invalid.
    fn handle_part_or_fault(
        &mut self,
        sender_index: u64,
        Part(receiver_index, commitment, ser_row, rows): Part,
    ) -> Result<Option<Poly>, PartFault> {
        if rows.len() != self.pub_keys.len() {
            return Err(PartFault::RowCount);
        }
        if receiver_index != self.our_index {
            return Ok(None);
        }
        if let Some(state) = self.parts.get(&sender_index) {
            if state.commitment != commitment {
                return Err(PartFault::MultipleParts);
            }
            return Ok(None); // We already handled this `Part` before.
        }
        let commitment_row = commitment.row(self.our_index + 1);
        // Retrieve our own row's commitment, and store the full commitment.
        let _ = self
            .parts
            .insert(sender_index, ProposalState::new(commitment));

        let row: Poly = deserialize(&ser_row).map_err(|_| PartFault::DeserializeRow)?;
        if row.commitment() != commitment_row {
            return Err(PartFault::RowCommitment);
        }
        Ok(Some(row))
    }

    /// Handles a `Commitment` message.
    fn handle_commitment_or_fault(
        &mut self,
        sender_index: u64,
        Commitment(proposer_index, receiver_index, ser_val, values): Commitment,
    ) -> Result<(), CommitmentFault> {
        if values.len() != self.pub_keys.len() {
            return Err(CommitmentFault::ValueCount);
        }
        if receiver_index != self.our_index {
            return Ok(());
        }
        {
            let part = self
                .parts
                .get_mut(&proposer_index)
                .ok_or(CommitmentFault::MissingPart)?;
            if !part.commitments.insert(sender_index) {
                return Ok(()); // We already handled this `Commitment` before.
            }
            let our_index = self.our_index;

            let val = deserialize::<FieldWrap<Fr>>(&ser_val)
                .map_err(|_| CommitmentFault::DeserializeValue)?
                .into_inner();
            if part.commitment.evaluate(our_index + 1, sender_index + 1) != G1Affine::one().mul(val)
            {
                return Err(CommitmentFault::ValueCommitment);
            }
            let _ = part.values.insert(sender_index + 1, val);
        }

        {
            let part = self
                .parts
                .get_mut(&sender_index)
                .ok_or(CommitmentFault::MissingPart)?;
            part.enc_values = values;
        }

        Ok(())
    }
}

// https://github.com/rust-lang/rust/issues/52560
// Cannot derive Debug without changing the type parameter
impl<S: SecretId> Debug for KeyGen<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "KeyGen{{{:?}}}", self.our_id)
    }
}

#[cfg(test)]
impl<S: SecretId> KeyGen<S> {
    /// Returns the list of the final participants.
    pub fn pub_keys(&self) -> &BTreeSet<S::PublicId> {
        &self.pub_keys
    }

    /// Initialize an instance with some pre-defined value, only for testing usage.
    pub fn initialize_for_test(
        our_id: S::PublicId,
        our_index: u64,
        pub_keys: BTreeSet<S::PublicId>,
        threshold: usize,
        phase: Phase,
    ) -> KeyGen<S> {
        assert!(pub_keys.len() >= threshold);
        KeyGen::<S> {
            our_id,
            our_index,
            pub_keys: pub_keys.clone(),
            encryptor: Encryptor::new(&pub_keys),
            parts: BTreeMap::new(),
            threshold,
            phase,
            initalization_accumulator: InitializationAccumulator::new(),
            contribution_accumulator: ContributionAccumulator::new(pub_keys.clone()),
            complaints_accumulator: ComplaintsAccumulator::new(pub_keys, threshold),
        }
    }
}

/// `Commitment` faulty entries.
#[derive(
    Clone, Copy, Eq, err_derive::Error, PartialEq, Debug, Serialize, Deserialize, PartialOrd, Ord,
)]
pub enum CommitmentFault {
    /// The number of values differs from the number of nodes.
    #[error(display = "The number of values differs from the number of nodes")]
    ValueCount,
    /// No corresponding Part received.
    #[error(display = "No corresponding Part received")]
    MissingPart,
    /// Value decryption failed.
    #[error(display = "Value decryption failed")]
    DecryptValue,
    /// Value deserialization failed.
    #[error(display = "Value deserialization failed")]
    DeserializeValue,
    /// Value doesn't match the commitment.
    #[error(display = "Value doesn't match the commitment")]
    ValueCommitment,
}

/// `Part` faulty entries.
#[derive(
    Clone, Copy, Eq, err_derive::Error, PartialEq, Debug, Serialize, Deserialize, PartialOrd, Ord,
)]
pub enum PartFault {
    /// The number of rows differs from the number of nodes.
    #[error(display = "The number of rows differs from the number of nodes")]
    RowCount,
    /// Received multiple different Part messages from the same sender.
    #[error(display = "Received multiple different Part messages from the same sender")]
    MultipleParts,
    /// Could not decrypt our row in the Part message.
    #[error(display = "Could not decrypt our row in the Part message")]
    DecryptRow,
    /// Could not deserialize our row in the Part message.
    #[error(display = "Could not deserialize our row in the Part message")]
    DeserializeRow,
    /// Row does not match the commitment.
    #[error(display = "Row does not match the commitment")]
    RowCommitment,
}
