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

use bincode::{self, deserialize, serialize};
use blsttc::{
    ff::Field,
    group::CurveAffine,
    poly::{BivarCommitment, BivarPoly, Poly},
    serde_impl::FieldWrap,
    Fr, G1Affine,
};
pub use blsttc::{PublicKeySet, SecretKeyShare};
use encryptor::{Encryptor, Iv, Key};
use message::Message;
use outcome::Outcome;
use rand::{self, RngCore};
use serde_derive::{Deserialize, Serialize};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::{
    fmt::{self, Debug, Formatter},
    mem,
};
use xor_name::XorName;

/// A local error while handling a message, that was not caused by that message being invalid.
#[non_exhaustive]
#[derive(Clone, Eq, thiserror::Error, PartialEq, Debug)]
pub enum Error {
    /// Unknown error.
    #[error("Unknown")]
    Unknown,
    /// Unknown sender.
    #[error("Unknown sender")]
    UnknownSender,
    /// Failed to serialize message.
    #[error("Serialization error: {}", _0)]
    Serialization(String),
    /// Network error from Quic-P2P.
    #[error("QuicP2P error: {}", _0)]
    QuicP2P(String),
    /// Failed to encrypt message.
    #[error("Encryption error")]
    Encryption,
    /// Failed to finalize Complaint phase due to too many non-voters.
    #[error("Too many non-voters error")]
    TooManyNonVoters(BTreeSet<u64>),
    /// Unexpected phase.
    #[error("Unexpected phase")]
    UnexpectedPhase { expected: Phase, actual: Phase },
    /// Ack on a missed part.
    #[error("ACK on missed part")]
    MissingPart,
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(err: Box<bincode::ErrorKind>) -> Error {
        Error::Serialization(format!("{:?}", err))
    }
}

/// A contribution by a node for the key generation. The part shall only be handled by the receiver.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Part {
    // Index of the peer that expected to receive this Part.
    receiver: u64,
    // Our poly-commitment.
    commitment: BivarCommitment,
    // serialized row for the receiver.
    ser_row: Vec<u8>,
    // Encrypted rows from the sender.
    enc_rows: Vec<Vec<u8>>,
}

impl Debug for Part {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Part")
            .field(&format!("<receiver {}>", &self.receiver))
            .field(&format!("<degree {}>", self.commitment.degree()))
            .field(&format!("<{} rows>", self.enc_rows.len()))
            .finish()
    }
}

/// A confirmation that we have received and verified a validator's part. It must be sent to
/// all participating nodes and handled by all of them, including ourselves.
///
/// The message is only produced after we verified our row against the ack in the `Part`.
/// For each node, it contains `proposal_index, receiver_index, serialised value for the receiver,
/// encrypted values from the sender`.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Acknowledgment(pub u64, u64, Vec<u8>, Vec<Vec<u8>>);

impl Debug for Acknowledgment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Acknowledgment")
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
    /// The verified values we received from `Acknowledgment` messages.
    values: BTreeMap<u64, Fr>,
    /// The encrypted values received from the proposor.
    enc_values: Vec<Vec<u8>>,
    /// The nodes which have committed.
    acks: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commitment: BivarCommitment) -> ProposalState {
        ProposalState {
            commitment,
            values: BTreeMap::new(),
            enc_values: Vec::new(),
            acks: BTreeSet::new(),
        }
    }

    fn is_complete(&self, threshold: usize) -> bool {
        self.acks.len() > threshold
    }
}

impl<'a> serde::Deserialize<'a> for ProposalState {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let (commitment, values, enc_values, acks) = serde::Deserialize::deserialize(deserializer)?;
        let values: Vec<(u64, FieldWrap<Fr>)> = values;
        Ok(Self {
            commitment,
            values: values
                .into_iter()
                .map(|(index, fr)| (index, fr.0))
                .collect(),
            enc_values,
            acks,
        })
    }
}

/// The outcome of handling and verifying a `Part` message.
pub enum PartOutcome {
    /// The message was valid: the part of it that was encrypted to us matched the public
    /// ack, so we can multicast an `Acknowledgment` message for it. If we have already handled the
    /// same `Part` before, this contains `None` instead.
    Valid(Option<Acknowledgment>),
    /// The message was invalid: We now know that the proposer is faulty.
    Invalid(PartFault),
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
struct InitializationAccumulator {
    senders: BTreeSet<u64>,
    initializations: BTreeMap<(usize, usize, BTreeSet<XorName>), usize>,
}

impl InitializationAccumulator {
    fn new() -> InitializationAccumulator {
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
        member_list: BTreeSet<XorName>,
    ) -> Option<(usize, usize, BTreeSet<XorName>)> {
        if !self.senders.insert(sender) {
            return None;
        }

        let paras = (m, n, member_list);
        let value = self.initializations.entry(paras.clone()).or_insert(0);
        *value += 1;

        if *value >= m {
            Some(paras)
        } else {
            None
        }
    }
}

#[derive(Default)]
struct ComplaintsAccumulator {
    names: BTreeSet<XorName>,
    threshold: usize,
    // Indexed by complaining targets.
    complaints: BTreeMap<XorName, BTreeSet<XorName>>,
}

impl ComplaintsAccumulator {
    fn new(names: BTreeSet<XorName>, threshold: usize) -> ComplaintsAccumulator {
        ComplaintsAccumulator {
            names,
            threshold,
            complaints: BTreeMap::new(),
        }
    }

    // TODO: accusation shall be validated.
    fn add_complaint(&mut self, sender_id: XorName, target_id: XorName, _msg: Vec<u8>) {
        if !self.names.contains(&sender_id) || !self.names.contains(&target_id) {
            return;
        }

        match self.complaints.entry(target_id) {
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
    fn finalize_complaining_phase(&self) -> BTreeSet<XorName> {
        let mut invalid_peers = BTreeSet::new();

        // Counts for how many times a member missed complaining against others validly.
        // If missed too many times, such member shall be considered as invalid directly.
        let mut counts: BTreeMap<XorName, usize> = BTreeMap::new();

        for (target_id, accusers) in self.complaints.iter() {
            if accusers.len() > self.names.len() - self.threshold {
                let _ = invalid_peers.insert(*target_id);
                for peer in self.names.iter() {
                    if !accusers.contains(peer) {
                        *counts.entry(*peer).or_insert(0usize) += 1;
                    }
                }
            }
        }
        for (peer, times) in counts {
            if times > self.names.len() / 2 {
                let _ = invalid_peers.insert(peer);
            }
        }

        invalid_peers
    }
}

pub type MessageAndTarget = (XorName, Message);

/// An algorithm for dealerless distributed key generation.
///
/// This is trying to follow the protocol as suggested at
/// <https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md#distributed-key-generation-dkg-protocol>
///
/// A normal usage flow will be:
///
/// 1. Call [`initialize`](Self::initialize) first to generate an instance.
/// 2. Multicasting the return [`Message`] to all participants.
/// 3. Call [`handle_message`](Self::handle_message) function to handle the incoming `Message` and
///    multicasting the resulting `Message`s (if any) to all participants.
/// 4. Call [`timed_phase_transition`](Self::timed_phase_transition) to complete the complaining
///    phase.
/// 5. Repeat step 3 when there is incoming `Message`.
/// 6. Call [`generate_keys`](Self::generate_keys) to get the public-key set and secret-key share,
///    if the procedure finalized.
pub struct KeyGen {
    /// Our node ID.
    our_id: XorName,
    /// Our node index.
    our_index: u64,
    /// The names of all nodes, by node ID.
    names: BTreeSet<XorName>,
    /// Carry out encryption work during the DKG process.
    encryptor: Encryptor,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
    /// Current DKG phase.
    phase: Phase,
    /// Accumulates initializations.
    initalization_accumulator: InitializationAccumulator,
    /// Accumulates complaints.
    complaints_accumulator: ComplaintsAccumulator,
    /// Pending complain messages.
    pending_complain_messages: Vec<Message>,
    /// Cached messages to be used for reply unhandable.
    message_cache: BTreeMap<XorName, Message>,
}

impl KeyGen {
    /// Creates a new `KeyGen` instance, together with the `Initial` message that should be
    /// multicast to all nodes.
    pub fn initialize(
        our_id: XorName,
        threshold: usize,
        names: BTreeSet<XorName>,
    ) -> Result<(KeyGen, Vec<MessageAndTarget>), Error> {
        if names.len() < threshold {
            return Err(Error::Unknown);
        }
        let our_index = if let Some(index) = names.iter().position(|id| *id == our_id) {
            index as u64
        } else {
            return Err(Error::Unknown);
        };

        let key_gen = KeyGen {
            our_id,
            our_index,
            names: names.clone(),
            encryptor: Encryptor::new(&names),
            parts: BTreeMap::new(),
            threshold,
            phase: Phase::Initialization,
            initalization_accumulator: InitializationAccumulator::new(),
            complaints_accumulator: ComplaintsAccumulator::new(names.clone(), threshold),
            pending_complain_messages: Vec::new(),
            message_cache: BTreeMap::new(),
        };

        let msg = Message::Initialization {
            key_gen_id: our_index,
            m: threshold,
            n: names.len(),
            member_list: names.clone(),
        };
        let messages: Vec<_> = names.iter().map(|name| (*name, msg.clone())).collect();

        Ok((key_gen, messages))
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Dispatching an incoming dkg message.
    pub fn handle_message<R: RngCore>(
        &mut self,
        rng: &mut R,
        msg: Message,
    ) -> Result<Vec<MessageAndTarget>, Error> {
        if self.is_finalized() {
            return Ok(Vec::new());
        }

        self.process_message(rng, msg)
    }

    /// Cached message will be returned as a list,
    /// with Initialization messages on top and Proposal behind.
    /// They shall get handled in such order on receiver side as well.
    pub fn get_cached_message(&self) -> Vec<Message> {
        let mut result = Vec::new();
        result.extend(
            self.message_cache
                .iter()
                .filter_map(|(_, msg)| match msg {
                    Message::Initialization { .. } => Some(msg.clone()),
                    _ => None,
                })
                .collect::<Vec<Message>>(),
        );
        result.extend(
            self.message_cache
                .iter()
                .filter_map(|(_, msg)| match msg {
                    Message::Proposal { .. } => Some(msg.clone()),
                    _ => None,
                })
                .collect::<Vec<Message>>(),
        );
        result
    }

    /// Handle upper layer cached messages even before this DKG session got started.
    /// Returns with messages need to be broadcast to all,
    /// AND unhandable messages need to be sent to the creator.
    /// It is also being used when handle message_history due to unhandable.
    pub fn handle_pre_session_messages<R: RngCore>(
        &mut self,
        rng: &mut R,
        mut cache_messages: Vec<Message>,
    ) -> (Vec<MessageAndTarget>, Vec<MessageAndTarget>) {
        let mut msgs = Vec::new();
        let mut updated = false;
        loop {
            trace!("new round polling history messages");
            let pending_messages = std::mem::take(&mut cache_messages);
            for message in pending_messages {
                if let Ok(new_messages) = self.process_message(rng, message.clone()) {
                    if self.is_finalized() {
                        return (Vec::new(), Vec::new());
                    }
                    msgs.extend(new_messages);
                    updated = true;
                } else {
                    trace!("pushing back history message {:?}", message);
                    cache_messages.push(message);
                }
            }
            if !updated {
                break;
            } else {
                updated = false;
            }
        }

        let mut unhandables = Vec::new();
        for msg in cache_messages {
            let sender = if let Some(name) = self.node_id_from_index(msg.creator()) {
                name
            } else {
                warn!(
                    "cannot get name of index {:?} among {:?}",
                    msg.creator(),
                    self.names
                );
                continue;
            };
            unhandables.push((sender, msg));
        }
        (msgs, unhandables)
    }

    fn process_message<R: RngCore>(
        &mut self,
        rng: &mut R,
        msg: Message,
    ) -> Result<Vec<MessageAndTarget>, Error> {
        trace!(
            "{:?} with phase {:?} handle DKG message {:?}-{:?}",
            self,
            self.phase,
            msg.id(),
            msg
        );
        let result = match msg.clone() {
            Message::Initialization {
                key_gen_id,
                m,
                n,
                member_list,
            } => {
                let _ = self.message_cache.insert(msg.id(), msg);
                self.handle_initialization(rng, m, n, key_gen_id, member_list)
            }
            Message::Proposal { key_gen_id, part } => self.handle_proposal(key_gen_id, part),
            Message::Complaint {
                key_gen_id,
                target,
                msg,
            } => self.handle_complaint(key_gen_id, target, msg),
            Message::Justification {
                key_gen_id,
                keys_map,
            } => self.handle_justification(key_gen_id, keys_map),
            Message::Acknowledgment { key_gen_id, ack } => self.handle_ack(key_gen_id, ack),
        };
        self.multicasting_messages(result?)
    }

    // Handles an incoming initialize message. Creates the `Proposal` message once quorumn
    // agreement reached, and the message should be multicast to all nodes.
    fn handle_initialization<R: RngCore>(
        &mut self,
        rng: &mut R,
        m: usize,
        n: usize,
        sender: u64,
        member_list: BTreeSet<XorName>,
    ) -> Result<Vec<Message>, Error> {
        if self.phase != Phase::Initialization {
            return Ok(Vec::new());
        }

        if let Some((m, _n, member_list)) =
            self.initalization_accumulator
                .add_initialization(m, n, sender, member_list)
        {
            self.threshold = m;
            self.names = member_list;
            self.phase = Phase::Contribution;

            let mut rng = rng_adapter::RngAdapter(&mut *rng);
            let our_part = BivarPoly::random(self.threshold, &mut rng);
            let ack = our_part.commitment();
            let encrypt = |(i, name): (usize, &XorName)| {
                let row = our_part.row(i + 1);
                self.encryptor.encrypt(name, &serialize(&row)?)
            };
            let rows = self
                .names
                .iter()
                .enumerate()
                .map(encrypt)
                .collect::<Result<Vec<_>, Error>>()?;
            let result = self
                .names
                .iter()
                .enumerate()
                .map(|(idx, _pk)| {
                    let ser_row = serialize(&our_part.row(idx + 1))?;
                    Ok(Message::Proposal {
                        key_gen_id: self.our_index,
                        part: Part {
                            receiver: idx as u64,
                            commitment: ack.clone(),
                            ser_row,
                            enc_rows: rows.clone(),
                        },
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            return Ok(result);
        }
        Ok(Vec::new())
    }

    // Handles a `Proposal` message during the `Contribution` phase.
    // When there is an invalidation happens, holds the `Complaint` message till broadcast out
    // when `finalize_contributing` being called.
    fn handle_proposal(&mut self, sender_index: u64, part: Part) -> Result<Vec<Message>, Error> {
        if self.phase == Phase::Initialization {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Contribution,
                actual: self.phase,
            });
        } else if !(self.phase == Phase::Contribution || self.phase == Phase::Commitment) {
            return Ok(Vec::new());
        }

        let row = match self.handle_part_or_fault(sender_index, part.clone()) {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(Vec::new()),
            Err(_fault) => {
                let msg = Message::Proposal {
                    key_gen_id: sender_index,
                    part,
                };
                debug!(
                    "{:?} complain {:?} with Error {:?} when handling a proposal",
                    self, sender_index, _fault
                );
                let invalid_contribute = serialize(&msg)?;
                self.pending_complain_messages.push(Message::Complaint {
                    key_gen_id: self.our_index,
                    target: sender_index,
                    msg: invalid_contribute,
                });
                return Ok(Vec::new());
            }
        };

        // The row is valid. Encrypt one value for each node and broadcast `Acknowledgment`.
        let mut values = Vec::new();
        let mut enc_values = Vec::new();
        for (index, pk) in self.names.iter().enumerate() {
            let val = row.evaluate(index + 1);
            let ser_val = serialize(&FieldWrap(val))?;
            enc_values.push(self.encryptor.encrypt(pk, &ser_val)?);
            values.push(ser_val);
        }

        let result = self
            .names
            .iter()
            .enumerate()
            .map(|(idx, _pk)| Message::Acknowledgment {
                key_gen_id: self.our_index,
                ack: Acknowledgment(
                    sender_index,
                    idx as u64,
                    values[idx].clone(),
                    enc_values.clone(),
                ),
            })
            .collect();
        Ok(result)
    }

    // Handles an `Acknowledgment` message during the `Contribution` phase.
    // When there is an invalidation happens, holds the `Complaint` message till broadcast out
    // when `finalize_contributing` being called.
    fn handle_ack(
        &mut self,
        sender_index: u64,
        ack: Acknowledgment,
    ) -> Result<Vec<Message>, Error> {
        if self.phase == Phase::Initialization {
            return Err(Error::UnexpectedPhase {
                expected: Phase::Contribution,
                actual: self.phase,
            });
        } else if !(self.phase == Phase::Contribution || self.phase == Phase::Commitment) {
            return Ok(Vec::new());
        }

        match self.handle_ack_or_fault(sender_index, ack.clone()) {
            Ok(()) => {
                if self.all_contribution_received() {
                    if self.phase == Phase::Commitment {
                        self.become_finalization();
                    } else {
                        return Ok(self.finalize_contributing_phase());
                    }
                }
            }
            Err(AcknowledgmentFault::MissingPart) => {
                debug!(
                    "{:?} MissingPart on Ack not causing a complain, /
                        return with error to trigger an outside cache",
                    self
                );
                return Err(Error::MissingPart);
            }
            Err(fault) => {
                let msg = Message::Acknowledgment {
                    key_gen_id: sender_index,
                    ack,
                };
                debug!(
                    "{:?} complain {:?} with Error {:?}",
                    self, sender_index, fault
                );

                let invalid_ack = serialize(&msg)?;
                self.pending_complain_messages.push(Message::Complaint {
                    key_gen_id: self.our_index,
                    target: sender_index,
                    msg: invalid_ack,
                });
            }
        }
        Ok(Vec::new())
    }

    pub fn all_contribution_received(&self) -> bool {
        self.names.len() == self.parts.len()
            && self
                .parts
                .values()
                .all(|part| part.acks.len() == self.names.len())
    }

    fn finalize_contributing_phase(&mut self) -> Vec<Message> {
        self.phase = Phase::Complaining;

        for non_contributor in self.non_contributors().0 {
            debug!(
                "{:?} complain {:?} for non-contribution during Contribution phase",
                self, non_contributor
            );
            self.pending_complain_messages.push(Message::Complaint {
                key_gen_id: self.our_index,
                target: non_contributor,
                msg: b"Not contributed".to_vec(),
            });
        }
        debug!(
            "{:?} has {:?} complain message and is {:?} ready ({:?} - {:?})",
            self,
            self.pending_complain_messages.len(),
            self.is_ready(),
            self.complete_parts_count(),
            self.threshold,
        );
        // In case of ready, transit into `Finalization` phase.
        if self.is_ready() {
            self.become_finalization();
        }

        mem::take(&mut self.pending_complain_messages)
    }

    fn non_contributors(&self) -> (BTreeSet<u64>, BTreeSet<XorName>) {
        let mut non_idxes = BTreeSet::new();
        let mut non_ids = BTreeSet::new();
        let mut missing_times = BTreeMap::new();
        for (idx, name) in self.names.iter().enumerate() {
            if let Some(proposal_sate) = self.parts.get(&(idx as u64)) {
                if !proposal_sate.acks.contains(&(idx as u64)) {
                    let times = missing_times.entry(idx).or_insert_with(|| 0);
                    *times += 1;
                    if *times > self.names.len() / 2 {
                        let _ = non_idxes.insert(idx as u64);
                        let _ = non_ids.insert(*name);
                    }
                }
            } else {
                let _ = non_idxes.insert(idx as u64);
                let _ = non_ids.insert(*name);
            }
        }
        (non_idxes, non_ids)
    }

    // TODO: So far this function has to be called externally to indicates a completion of the
    //       contribution phase. That is, the owner of the key_gen instance has to wait for a fixed
    //       interval, say an expected timer of 5 minutes, to allow the messages to be exchanged.
    //       May need to be further verified whether there is a better approach.
    pub fn timed_phase_transition<R: RngCore>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<MessageAndTarget>, Error> {
        trace!("{:?} current phase is {:?}", self, self.phase);
        let result = match self.phase {
            Phase::Contribution => Ok(self.finalize_contributing_phase()),
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
        };
        self.multicasting_messages(result?)
    }

    // Specify the receiver of the DKG messages explicitly
    // to avoid un-necessary broadcasting.
    fn multicasting_messages(
        &mut self,
        messages: Vec<Message>,
    ) -> Result<Vec<MessageAndTarget>, Error> {
        let mut messaging = Vec::new();
        for message in messages {
            match message {
                Message::Proposal { ref part, .. } => {
                    // Proposal to us cannot be used by other.
                    // So the cache must be carried out on sender side.
                    let _ = self.message_cache.insert(message.id(), message.clone());

                    let receiver = if let Some(name) = self.node_id_from_index(part.receiver) {
                        name
                    } else {
                        warn!(
                            "For a Proposal, Cannot get name of index {:?} among {:?}",
                            part.receiver, self.names
                        );
                        continue;
                    };
                    messaging.push((receiver, message));
                }
                Message::Acknowledgment { ref ack, .. } => {
                    let receiver = if let Some(name) = self.node_id_from_index(ack.1) {
                        name
                    } else {
                        warn!(
                            "For an Acknowledgement, Cannot get name of index {:?} among {:?}",
                            ack.1, self.names
                        );
                        continue;
                    };
                    messaging.push((receiver, message));
                }
                _ => {
                    for name in &self.names {
                        messaging.push((*name, message.clone()));
                    }
                }
            }
        }
        Ok(messaging)
    }

    // Handles a `Complaint` message.
    fn handle_complaint(
        &mut self,
        sender_index: u64,
        target_index: u64,
        invalid_msg: Vec<u8>,
    ) -> Result<Vec<Message>, Error> {
        if self.phase != Phase::Complaining {
            trace!("To avoid triggering AE pattern, skip this so far");
            return Ok(Vec::new());
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
    ) -> Result<Vec<Message>, Error> {
        let failings = self.complaints_accumulator.finalize_complaining_phase();

        if failings.len() >= self.names.len() - self.threshold {
            let mut result = BTreeSet::new();
            failings.iter().for_each(|pk| {
                if let Some(index) = self.node_index(pk) {
                    let _ = result.insert(index);
                }
            });
            trace!("Finalized with too many failing voters");
            return Err(Error::TooManyNonVoters(result));
        }

        let mut result = Vec::new();
        // Sending out a Justification message if find self is failed.
        if failings.contains(&self.our_id) {
            result.push(Message::Justification {
                key_gen_id: self.our_index,
                keys_map: self.encryptor.keys_map(),
            });
        }

        // TODO: when there is consensused failing members, we shall transit into Justification
        //       phase to wait for the accused member send us the encryption keys to recover.
        //       However, the accusation could also be `non-contribution`, which disables recovery.
        //       So currently we skip the Justification phase, assuming all the consensused
        //       complained members are really invalid, and transit into the Commitment phase to
        //       start a new round of DKG without the complained members.

        if !failings.is_empty() {
            for failing in failings.iter() {
                let _ = self.names.remove(failing);
            }
            self.our_index = self.node_index(&self.our_id).ok_or(Error::Unknown)?;
        } else if self.is_ready() {
            self.become_finalization();
            return Ok(Vec::new());
        }

        self.phase = Phase::Commitment;
        self.parts = BTreeMap::new();

        let mut rng = rng_adapter::RngAdapter(&mut *rng);
        let our_part = BivarPoly::random(self.threshold, &mut rng);
        let justify = our_part.commitment();
        let encrypt = |(i, name): (usize, &XorName)| {
            let row = our_part.row(i + 1);
            self.encryptor.encrypt(name, &serialize(&row)?)
        };
        let rows = self
            .names
            .iter()
            .enumerate()
            .map(encrypt)
            .collect::<Result<Vec<_>, Error>>()?;

        self.names.iter().enumerate().for_each(|(idx, _pk)| {
            if let Ok(ser_row) = serialize(&our_part.row(idx + 1)) {
                result.push(Message::Proposal {
                    key_gen_id: self.our_index,
                    part: Part {
                        receiver: idx as u64,
                        commitment: justify.clone(),
                        ser_row,
                        enc_rows: rows.clone(),
                    },
                });
            }
        });

        Ok(result)
    }

    // Handles a `Justification` message.
    fn handle_justification(
        &mut self,
        _sender_index: u64,
        _keys_map: BTreeMap<XorName, (Key, Iv)>,
    ) -> Result<Vec<Message>, Error> {
        // TODO: Need to decide how the justification and recover procedure take out.
        Ok(Vec::new())
    }

    fn become_finalization(&mut self) {
        self.phase = Phase::Finalization;
        self.pending_complain_messages.clear();
    }

    /// Returns the index of the node, or `None` if it is unknown.
    fn node_index(&self, node_id: &XorName) -> Option<u64> {
        self.names
            .iter()
            .position(|id| id == node_id)
            .map(|index| index as u64)
    }

    /// Returns the id of the index, or `None` if it is unknown.
    pub fn node_id_from_index(&self, node_index: u64) -> Option<XorName> {
        for (i, name) in self.names.iter().enumerate() {
            if i == node_index as usize {
                return Some(*name);
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

    // Returns `true` if all parts are complete to safely generate the new key.
    fn is_ready(&self) -> bool {
        self.complete_parts_count() == self.names.len()
    }

    /// Returns `true` if in the phase of Finalization.
    pub fn is_finalized(&self) -> bool {
        let result = self.phase == Phase::Finalization;

        if !result {
            trace!("incompleted DKG session containing:");
            for (key, part) in self.parts.iter() {
                let acks: Vec<u64> = part.values.keys().cloned().collect();
                trace!("    Part from {:?}, and acks from {:?}", key, acks);
            }
        }
        result
    }

    /// Returns the new secret key share and the public key set.
    pub fn generate_keys(&self) -> Option<(BTreeSet<XorName>, Outcome)> {
        if !self.is_finalized() {
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
            self.names.clone(),
            Outcome::new(pk_commitment.into(), sk, self.our_index as usize),
        ))
    }

    /// This function shall be called when the DKG procedure not reach Finalization phase and before
    /// discarding the instace. It returns potential invalid peers that causing the blocking, if
    /// any and provable.
    pub fn possible_blockers(&self) -> BTreeSet<XorName> {
        let mut result = BTreeSet::new();
        match self.phase {
            Phase::Initialization => {
                for (index, name) in self.names.iter().enumerate() {
                    if !self
                        .initalization_accumulator
                        .senders
                        .contains(&(index as u64))
                    {
                        let _ = result.insert(*name);
                    }
                }
            }
            Phase::Contribution => result = self.non_contributors().1,
            Phase::Complaining => {
                // Non-voters shall already be returned within the error of the
                // finalize_complaint_phase function call.
            }
            Phase::Justification | Phase::Commitment => {
                // As Complaint phase gets completed, it is expected that all nodes are now
                // in these two phases. Hence here a strict rule is undertaken that: any missing
                // vote will be considered as a potential non-voter.
                for part in self.parts.values() {
                    for (index, name) in self.names.iter().enumerate() {
                        if !part.acks.contains(&(index as u64)) {
                            let _ = result.insert(*name);
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
        Part {
            receiver,
            commitment,
            ser_row,
            enc_rows,
        }: Part,
    ) -> Result<Option<Poly>, PartFault> {
        if enc_rows.len() != self.names.len() {
            return Err(PartFault::RowCount);
        }
        if receiver != self.our_index {
            return Ok(None);
        }
        if let Some(state) = self.parts.get(&sender_index) {
            if state.commitment != commitment {
                return Err(PartFault::MultipleParts);
            }
            return Ok(None); // We already handled this `Part` before.
        }
        let ack_row = commitment.row(self.our_index + 1);
        // Retrieve our own row's commitment, and store the full commitment.
        let _ = self
            .parts
            .insert(sender_index, ProposalState::new(commitment));

        let row: Poly = deserialize(&ser_row).map_err(|_| PartFault::DeserializeRow)?;
        if row.commitment() != ack_row {
            return Err(PartFault::RowAcknowledgment);
        }
        Ok(Some(row))
    }

    /// Handles an acknowledgment.
    fn handle_ack_or_fault(
        &mut self,
        sender_index: u64,
        Acknowledgment(proposer_index, receiver_index, ser_val, values): Acknowledgment,
    ) -> Result<(), AcknowledgmentFault> {
        if values.len() != self.names.len() {
            return Err(AcknowledgmentFault::ValueCount);
        }
        if receiver_index != self.our_index {
            return Ok(());
        }
        {
            let part = self
                .parts
                .get_mut(&proposer_index)
                .ok_or(AcknowledgmentFault::MissingPart)?;
            if !part.acks.insert(sender_index) {
                return Ok(()); // We already handled this `Acknowledgment` before.
            }
            let our_index = self.our_index;

            let val = deserialize::<FieldWrap<Fr>>(&ser_val)
                .map_err(|_| AcknowledgmentFault::DeserializeValue)?
                .into_inner();
            if part.commitment.evaluate(our_index + 1, sender_index + 1) != G1Affine::one().mul(val)
            {
                return Err(AcknowledgmentFault::ValueAcknowledgment);
            }
            let _ = part.values.insert(sender_index + 1, val);
        }

        {
            let part = self
                .parts
                .get_mut(&sender_index)
                .ok_or(AcknowledgmentFault::MissingPart)?;
            part.enc_values = values;
        }

        Ok(())
    }
}

impl Debug for KeyGen {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "KeyGen{{{:?}}}", self.our_id)
    }
}

#[cfg(test)]
impl KeyGen {
    /// Returns the name list of the final participants.
    pub fn names(&self) -> &BTreeSet<XorName> {
        &self.names
    }

    /// Initialize an instance with some pre-defined value, only for testing usage.
    pub fn initialize_for_test(
        our_id: XorName,
        our_index: u64,
        names: BTreeSet<XorName>,
        threshold: usize,
        phase: Phase,
    ) -> KeyGen {
        assert!(names.len() >= threshold);
        KeyGen {
            our_id,
            our_index,
            names: names.clone(),
            encryptor: Encryptor::new(&names),
            parts: BTreeMap::new(),
            threshold,
            phase,
            initalization_accumulator: InitializationAccumulator::new(),
            complaints_accumulator: ComplaintsAccumulator::new(names, threshold),
            pending_complain_messages: Vec::new(),
            message_cache: BTreeMap::new(),
        }
    }
}

/// `Acknowledgment` faulty entries.
#[non_exhaustive]
#[derive(
    Clone, Copy, Eq, thiserror::Error, PartialEq, Debug, Serialize, Deserialize, PartialOrd, Ord,
)]
pub enum AcknowledgmentFault {
    /// The number of values differs from the number of nodes.
    #[error("The number of values differs from the number of nodes")]
    ValueCount,
    /// No corresponding Part received.
    #[error("No corresponding Part received")]
    MissingPart,
    /// Value decryption failed.
    #[error("Value decryption failed")]
    DecryptValue,
    /// Value deserialization failed.
    #[error("Value deserialization failed")]
    DeserializeValue,
    /// Value doesn't match the ack.
    #[error("Value doesn't match the ack")]
    ValueAcknowledgment,
}

/// `Part` faulty entries.
#[non_exhaustive]
#[derive(
    Clone, Copy, Eq, thiserror::Error, PartialEq, Debug, Serialize, Deserialize, PartialOrd, Ord,
)]
pub enum PartFault {
    /// The number of rows differs from the number of nodes.
    #[error("The number of rows differs from the number of nodes")]
    RowCount,
    /// Received multiple different Part messages from the same sender.
    #[error("Received multiple different Part messages from the same sender")]
    MultipleParts,
    /// Could not decrypt our row in the Part message.
    #[error("Could not decrypt our row in the Part message")]
    DecryptRow,
    /// Could not deserialize our row in the Part message.
    #[error("Could not deserialize our row in the Part message")]
    DeserializeRow,
    /// Row does not match the ack.
    #[error("Row does not match the ack")]
    RowAcknowledgment,
}
