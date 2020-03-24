// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod dkg_result;
pub mod message;
mod rng_adapter;

use crate::id::{PublicId, SecretId};
use crate::key_gen::message::DkgMessage;
use dkg_result::DkgResult;
use failure::Fail;
use maidsafe_utilities::serialisation;
use rand;
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
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// Unknown error.
    #[fail(display = "Unknown")]
    Unknown,
    /// Unknown sender.
    #[fail(display = "Unknown sender")]
    UnknownSender,
    /// Failed to serialize message.
    #[fail(display = "Serialization error: {}", _0)]
    Serialization(String),
    /// Failed to encrypt message.
    #[fail(display = "Encryption error")]
    Encryption,
}

impl From<serialisation::SerialisationError> for Error {
    fn from(err: serialisation::SerialisationError) -> Error {
        Error::Serialization(format!("{:?}", err))
    }
}

/// A contribution by a node for the key generation. It must to be sent to all participating
/// nodes and handled by all of them, including the one that produced it.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Part(BivarCommitment, Vec<Vec<u8>>);

impl Debug for Part {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Part")
            .field(&format!("<degree {}>", self.0.degree()))
            .field(&format!("<{} rows>", self.1.len()))
            .finish()
    }
}

/// A confirmation that we have received and verified a validator's part. It must be sent to
/// all participating nodes and handled by all of them, including ourselves.
///
/// The message is only produced after we verified our row against the commitment in the `Part`.
/// For each node, it contains one encrypted value of that row.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Commitment(u64, Vec<Vec<u8>>);

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Commitment")
            .field(&self.0)
            .field(&format!("<{} values>", self.1.len()))
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
    /// The nodes which have committed.
    commitments: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commitment: BivarCommitment) -> ProposalState {
        ProposalState {
            commitment,
            values: BTreeMap::new(),
            commitments: BTreeSet::new(),
        }
    }

    /// Returns `true` if at least `2 * threshold + 1` nodes have committed.
    fn is_complete(&self, threshold: usize) -> bool {
        self.commitments.len() > 2 * threshold
    }
}

impl<'a> serde::Deserialize<'a> for ProposalState {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let (commitment, values, commitments) = serde::Deserialize::deserialize(deserializer)?;
        let values: Vec<(u64, FieldWrap<Fr>)> = values;
        Ok(Self {
            commitment,
            values: values
                .into_iter()
                .map(|(index, fr)| (index, fr.0))
                .collect(),
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

#[derive(Deserialize, PartialEq)]
pub enum DkgPhases {
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
        m: usize,
        n: usize,
        sender: u64,
        member_list: BTreeSet<P>,
    ) -> Option<(usize, usize, BTreeSet<P>)> {
        if self.senders.insert(sender) {
            return None;
        }

        let paras = (m, n, member_list);
        if let Some(value) = self.initializations.get_mut(&paras) {
            *value += 1;
            if *value > (2 * m + 1) {
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
}

#[derive(Default)]
struct ComplaintsAccumulator<P: PublicId> {
    pub_keys: BTreeSet<P>,
    // Indexed by complaining targets.
    complaints: BTreeMap<P, BTreeSet<P>>,
}

impl<P: PublicId> ComplaintsAccumulator<P> {
    fn new(pub_keys: BTreeSet<P>) -> ComplaintsAccumulator<P> {
        ComplaintsAccumulator {
            pub_keys,
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

    // note: there is nothing in this signature that lets us know
    // what the returned peers are and why they are returned.
    fn finalize_complaining_phase(&self) -> BTreeSet<P> {
        let mut invalid_peers = BTreeSet::new();

        // Counts for how many times a member missed complaining against others validly.
        // If missed too many times, such member shall be considered as invalid directly.
        let mut counts: BTreeMap<P, usize> = BTreeMap::new();

        for (target_id, accusers) in self.complaints.iter() {
            if accusers.len() * 3 > self.pub_keys.len() * 2 {
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
///   b, multicasting the return `DkgMessage` to all participants.
///   c, call `handle_message` function to handle the incoming `DkgMessage` and multicasting the
///      resulted `DkgMessage` (if has) to all participants.
///   d, call `finalize_complaining_phase` to complete the complaining phase. (This separate call may need to
///      depend on a separate timer & checker against the key generator's current status)
///   e, repeat step c when there is incoming `DkgMessage`.
///   f, call `generate` to get the public-key set and secret-key share, if the procedure finalized.
pub struct KeyGen<S: SecretId> {
    /// Our node ID.
    our_id: S::PublicId,
    /// Our node index.
    our_index: u64,
    /// The public keys of all nodes, by node ID.
    pub_keys: BTreeSet<S::PublicId>,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
    /// Current DKG phase.
    dkg_phase: DkgPhases,
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
    ) -> Result<(KeyGen<S>, DkgMessage<S::PublicId>), Error> {
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
            parts: BTreeMap::new(),
            threshold,
            dkg_phase: DkgPhases::Initialization,
            initalization_accumulator: InitializationAccumulator::new(),
            contribution_accumulator: ContributionAccumulator::new(pub_keys.clone()),
            complaints_accumulator: ComplaintsAccumulator::new(pub_keys.clone()),
        };

        Ok((
            key_gen,
            DkgMessage::Initialization {
                key_gen_id: our_index,
                m: threshold,
                n: pub_keys.len(),
                member_list: pub_keys,
            },
        ))
    }

    /// Dispatching an incoming dkg message.
    pub fn handle_message(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
        dkg_msg: DkgMessage<S::PublicId>,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        match dkg_msg {
            DkgMessage::Initialization {
                key_gen_id,
                m,
                n,
                member_list,
            } => self.handle_initialization(sec_key, rng, m, n, key_gen_id, member_list),
            DkgMessage::Contribution { key_gen_id, part } => {
                self.handle_contribution(sec_key, rng, key_gen_id, part)
            }
            DkgMessage::Complaint {
                key_gen_id,
                target,
                msg,
            } => self.handle_complaint(sec_key, key_gen_id, target, msg),
            DkgMessage::Justification { key_gen_id, part } => {
                self.handle_justification(sec_key, key_gen_id, part)
            }
            DkgMessage::Commitment {
                key_gen_id,
                commitment,
            } => {
                if let Err(err) = self.handle_commitment(sec_key, key_gen_id, commitment) {
                    Err(err)
                } else {
                    Ok(None)
                }
            }
        }
    }

    // Handles an incoming initialize message. Creates the `Contribution` message once quorumn
    // agreement reached, and the message should be multicast to all nodes.
    fn handle_initialization(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
        m: usize,
        n: usize,
        sender: u64,
        member_list: BTreeSet<S::PublicId>,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Initialization {
            return Err(Error::Unknown);
        }
        if let Some((m, n, member_list)) =
            self.initalization_accumulator
                .add_initialization(m, n, sender, member_list)
        {
            self.threshold = m;
            self.pub_keys = member_list;
            self.dkg_phase = DkgPhases::Contribution;

            let mut rng = rng_adapter::RngAdapter(&mut *rng);
            let our_part = BivarPoly::random(self.threshold, &mut rng);
            let commitment = our_part.commitment();
            let encrypt = |(i, pk): (usize, &S::PublicId)| {
                let row = our_part.row(i + 1);
                sec_key
                    .encrypt(pk, &serialisation::serialise(&row)?)
                    .ok_or(Error::Encryption)
            };
            let rows = self
                .pub_keys
                .iter()
                .enumerate()
                .map(encrypt)
                .collect::<Result<Vec<_>, Error>>()?;

            let mut result = Vec::new();
            result.push(DkgMessage::Contribution {
                key_gen_id: self.our_index,
                part: Part(commitment, rows),
            });
            return Ok(Some(result));
        }
        Ok(None)
    }

    // Handles a `Contribution` message.
    // If it is invalid, sends a `Complaint` message targeting the sender to be broadcast.
    // If all contributed, returns a `Commitment` message to be broadcast.
    fn handle_contribution(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
        sender_index: u64,
        part: Part,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Contribution {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;

        if !self
            .contribution_accumulator
            .add_contribution(sender_id, sender_index, part)
        {
            return Ok(None);
        }

        self.dkg_phase = DkgPhases::Complaining;

        let mut msgs = Vec::new();
        for ((sender_id, sender_index), part) in self.contribution_accumulator.contributions.clone()
        {
            match self.handle_part_or_fault(sec_key, sender_index, &sender_id, part.clone()) {
                Ok(Some(_row)) => {}
                Ok(None) => {}
                Err(_fault) => {
                    let msg = DkgMessage::Contribution::<S::PublicId> {
                        key_gen_id: sender_index,
                        part,
                    };
                    let invalid_contribute = serialisation::serialise(&msg)?;
                    msgs.push(DkgMessage::Complaint {
                        key_gen_id: self.our_index,
                        target: sender_index,
                        msg: invalid_contribute,
                    });
                }
            }
        }

        // In case of no complaints, calling finalize_complaining_phase to jump to `Justification` phase.
        // FIXME: May still be needed to be in `Complaining` phase, as others may complain?
        if msgs.is_empty() {
            if let Ok(msg) = self.finalize_complaining_phase(sec_key, rng) {
                msgs.push(msg);
            } else {
                return Err(Error::Unknown);
            }
        }

        Ok(Some(msgs))
    }

    // Handles a `Complaint` message.
    fn handle_complaint(
        &mut self,
        sec_key: &S,
        sender_index: u64,
        target_index: u64,
        invalid_msg: Vec<u8>,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Complaining {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;
        let target_id = self
            .node_id_from_index(target_index)
            .ok_or(Error::Unknown)?;

        self.complaints_accumulator
            .add_complaint(sender_id, target_id, invalid_msg);
        Ok(None)
    }

    // TODO: so far this function has to be called externally to indicates a completion of complain
    //       phase. May need to be further verified whether there is a better approach.
    pub fn finalize_complaining_phase(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
    ) -> Result<DkgMessage<S::PublicId>, Error> {
        let failings = self.complaints_accumulator.finalize_complaining_phase();
        if !failings.is_empty() {
            for failing in failings.iter() {
                let _ = self.pub_keys.remove(failing);
            }
            self.our_index = self.node_index(&self.our_id).ok_or(Error::Unknown)?;
        }

        self.dkg_phase = DkgPhases::Justification;
        self.parts = BTreeMap::new();

        let mut rng = rng_adapter::RngAdapter(&mut *rng);
        let our_part = BivarPoly::random(self.threshold, &mut rng);
        let justify = our_part.commitment();
        let encrypt = |(i, pk): (usize, &S::PublicId)| {
            let row = our_part.row(i + 1);
            sec_key
                .encrypt(pk, &serialisation::serialise(&row)?)
                .ok_or(Error::Encryption)
        };
        let rows = self
            .pub_keys
            .iter()
            .enumerate()
            .map(encrypt)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(DkgMessage::Justification {
            key_gen_id: self.our_index,
            part: Part(justify, rows),
        })
    }

    // Handles a `Justification` message.
    fn handle_justification(
        &mut self,
        sec_key: &S,
        sender_index: u64,
        part: Part,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Justification {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;
        let row = match self.handle_part_or_fault(sec_key, sender_index, &sender_id, part) {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(None),
            Err(_fault) => {
                // FIXME: shall we return back to complain phase ?
                return Ok(None);
            }
        };
        // The row is valid. Encrypt one value for each node and broadcast a `Commitment`.
        let mut values = Vec::new();
        for (index, pk) in self.pub_keys.iter().enumerate() {
            let val = row.evaluate(index + 1);
            let ser_val = serialisation::serialise(&FieldWrap(val))?;
            values.push(sec_key.encrypt(pk, ser_val).ok_or(Error::Encryption)?);
        }
        self.dkg_phase = DkgPhases::Commitment;
        let mut result = Vec::new();
        result.push(DkgMessage::Commitment {
            key_gen_id: self.our_index,
            commitment: Commitment(sender_index, values),
        });
        Ok(Some(result))
    }

    // Handles a `Commitment` message.
    fn handle_commitment(
        &mut self,
        sec_key: &S,
        sender_index: u64,
        commitment: Commitment,
    ) -> Result<CommitmentOutcome, Error> {
        if self.dkg_phase != DkgPhases::Commitment {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_index)
            .ok_or(Error::UnknownSender)?;

        Ok(
            match self.handle_commitment_or_fault(sec_key, &sender_id, sender_index, commitment) {
                Ok(()) => {
                    if self.is_ready() {
                        self.dkg_phase = DkgPhases::Finalization;
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
        self.complete_parts_count() > self.threshold
    }

    /// Returns the new secret key share and the public key set.
    pub fn generate_keys(&self) -> Result<(BTreeSet<S::PublicId>, DkgResult), Error> {
        if self.dkg_phase != DkgPhases::Finalization {
            return Err(Error::Unknown);
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
        Ok((
            self.pub_keys.clone(),
            DkgResult::new(pk_commitment.into(), sk),
        ))
    }

    /// Handles a `Part`, returns a `PartFault` if it is invalid.
    fn handle_part_or_fault(
        &mut self,
        sec_key: &S,
        sender_index: u64,
        sender_id: &S::PublicId,
        Part(commitment, rows): Part,
    ) -> Result<Option<Poly>, PartFault> {
        if rows.len() != self.pub_keys.len() {
            return Err(PartFault::RowCount);
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
        // We are a validator: Decrypt and deserialize our row and compare it to the commitment.
        let ser_row = sec_key
            .decrypt(sender_id, &rows[self.our_index as usize])
            .ok_or(PartFault::DecryptRow)?;
        let row: Poly =
            serialisation::deserialise(&ser_row).map_err(|_| PartFault::DeserializeRow)?;
        if row.commitment() != commitment_row {
            return Err(PartFault::RowCommitment);
        }
        Ok(Some(row))
    }

    /// Handles a `Commitment` message.
    fn handle_commitment_or_fault(
        &mut self,
        sec_key: &S,
        sender_id: &S::PublicId,
        sender_index: u64,
        Commitment(proposer_index, values): Commitment,
    ) -> Result<(), CommitmentFault> {
        if values.len() != self.pub_keys.len() {
            return Err(CommitmentFault::ValueCount);
        }
        let part = self
            .parts
            .get_mut(&proposer_index)
            .ok_or(CommitmentFault::MissingPart)?;
        if !part.commitments.insert(sender_index) {
            return Ok(()); // We already handled this `Commitment` before.
        }
        let our_index = self.our_index;
        // We are a validator: Decrypt and deserialize our value and compare it to the commitment.
        let ser_val = sec_key
            .decrypt(sender_id, &values[our_index as usize])
            .ok_or(CommitmentFault::DecryptValue)?;
        let val = serialisation::deserialise::<FieldWrap<Fr>>(&ser_val)
            .map_err(|_| CommitmentFault::DeserializeValue)?
            .into_inner();
        if part.commitment.evaluate(our_index + 1, sender_index + 1) != G1Affine::one().mul(val) {
            return Err(CommitmentFault::ValueCommitment);
        }
        let _ = part.values.insert(sender_index + 1, val);
        Ok(())
    }
}

// https://github.com/rust-lang/rust/issues/52560
// Cannot derive Debug without changing the type parameter
impl<S: SecretId> Debug for KeyGen<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "KeyGen{{our_id:{:?}, our_index:{:?}, pub_keys :{:?}, parts:{:?}, threshold:{:?}}}",
            self.our_id, self.our_index, self.pub_keys, self.parts, self.threshold
        )
    }
}

/// `Commitment` faulty entries.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Fail, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CommitmentFault {
    /// The number of values differs from the number of nodes.
    #[fail(display = "The number of values differs from the number of nodes")]
    ValueCount,
    /// No corresponding Part received.
    #[fail(display = "No corresponding Part received")]
    MissingPart,
    /// Value decryption failed.
    #[fail(display = "Value decryption failed")]
    DecryptValue,
    /// Value deserialization failed.
    #[fail(display = "Value deserialization failed")]
    DeserializeValue,
    /// Value doesn't match the commitment.
    #[fail(display = "Value doesn't match the commitment")]
    ValueCommitment,
}

/// `Part` faulty entries.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Fail, Serialize, Deserialize, PartialOrd, Ord)]
pub enum PartFault {
    /// The number of rows differs from the number of nodes.
    #[fail(display = "The number of rows differs from the number of nodes")]
    RowCount,
    /// Received multiple different Part messages from the same sender.
    #[fail(display = "Received multiple different Part messages from the same sender")]
    MultipleParts,
    /// Could not decrypt our row in the Part message.
    #[fail(display = "Could not decrypt our row in the Part message")]
    DecryptRow,
    /// Could not deserialize our row in the Part message.
    #[fail(display = "Could not deserialize our row in the Part message")]
    DeserializeRow,
    /// Row does not match the commitment.
    #[fail(display = "Row does not match the commitment")]
    RowCommitment,
}
