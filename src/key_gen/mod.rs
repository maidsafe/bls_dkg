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
    /// Unknown key set.
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
pub struct Commit(u64, Vec<Vec<u8>>);

impl Debug for Commit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Commit")
            .field(&self.0)
            .field(&format!("<{} values>", self.1.len()))
            .finish()
    }
}

/// The information needed to track a single proposer's secret sharing process.
#[derive(Debug, PartialEq, Eq)]
struct ProposalState {
    /// The proposer's commitment.
    commit: BivarCommitment,
    /// The verified values we received from `Commit` messages.
    values: BTreeMap<u64, Fr>,
    /// The nodes which have commited.
    commits: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commit: BivarCommitment) -> ProposalState {
        ProposalState {
            commit,
            values: BTreeMap::new(),
            commits: BTreeSet::new(),
        }
    }

    /// Returns `true` if at least `2 * threshold + 1` nodes have commited.
    fn is_complete(&self, threshold: usize) -> bool {
        self.commits.len() > 2 * threshold
    }
}

impl<'a> serde::Deserialize<'a> for ProposalState {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let (commit, values, commits) = serde::Deserialize::deserialize(deserializer)?;
        let values: Vec<(u64, FieldWrap<Fr>)> = values;
        Ok(Self {
            commit,
            values: values.into_iter().map(|(idx, fr)| (idx, fr.0)).collect(),
            commits,
        })
    }
}

/// The outcome of handling and verifying a `Part` message.
pub enum PartOutcome {
    /// The message was valid: the part of it that was encrypted to us matched the public
    /// commitment, so we can multicast an `Commit` message for it. If we have already handled the
    /// same `Part` before, this contains `None` instead.
    Valid(Option<Commit>),
    /// The message was invalid: We now know that the proposer is faulty.
    Invalid(PartFault),
}

/// The outcome of handling and verifying a `Commit` message.
pub enum CommitOutcome {
    /// The message was valid.
    Valid,
    /// The message was invalid: The sender is faulty.
    Invalid(CommitFault),
}

#[derive(Deserialize, PartialEq)]
pub enum DkgPhases {
    Initial,
    Contribute,
    Complain,
    Justification,
    Commitment,
    Finalize,
}

#[derive(Default)]
struct AccumulateInitial<P: PublicId> {
    senders: BTreeSet<u64>,
    received_initializes: BTreeMap<(usize, usize, BTreeSet<P>), usize>,
}

impl<P: PublicId> AccumulateInitial<P> {
    fn new() -> AccumulateInitial<P> {
        AccumulateInitial {
            senders: BTreeSet::new(),
            received_initializes: BTreeMap::new(),
        }
    }

    fn add_initial(
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
        if let Some(value) = self.received_initializes.get_mut(&paras) {
            *value += 1;
            if *value > (2 * m + 1) {
                return Some(paras);
            }
        } else {
            let _ = self.received_initializes.insert(paras, 1);
        }
        None
    }
}

#[derive(Default)]
struct AccumulateContribute<P: PublicId> {
    pub_keys: BTreeSet<P>,
    // Indexed by (id, idx), value is the `part`.
    contributes: BTreeMap<(P, u64), Part>,
}

impl<P: PublicId> AccumulateContribute<P> {
    fn new(pub_keys: BTreeSet<P>) -> AccumulateContribute<P> {
        AccumulateContribute {
            pub_keys,
            contributes: BTreeMap::new(),
        }
    }

    // returns `true` when received contributes from all expected senders.
    fn add_contribute(&mut self, sender_id: P, sender_idx: u64, part: Part) -> bool {
        if !self.pub_keys.contains(&sender_id) {
            return false;
        }
        let _ = self.contributes.insert((sender_id, sender_idx), part);
        self.contributes.len() == self.pub_keys.len()
    }
}

#[derive(Default)]
struct AccumulateComplain<P: PublicId> {
    pub_keys: BTreeSet<P>,
    // Indexed by complaining targets.
    complains: BTreeMap<P, BTreeSet<P>>,
}

impl<P: PublicId> AccumulateComplain<P> {
    fn new(pub_keys: BTreeSet<P>) -> AccumulateComplain<P> {
        AccumulateComplain {
            pub_keys,
            complains: BTreeMap::new(),
        }
    }

    // TODO: accusation shall be validated.
    fn add_complain(&mut self, sender_id: P, target_id: P, _msg: Vec<u8>) {
        if !self.pub_keys.contains(&sender_id) || !self.pub_keys.contains(&target_id) {
            return;
        }

        match self.complains.entry(target_id.clone()) {
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

    fn finalize_complain(&self) -> BTreeSet<P> {
        let mut failings = BTreeSet::new();

        // Counting for how many times a member missed complaining against others validly.
        // If missed too many times, such member shall be considered as invalid directly.
        let mut counting: BTreeMap<P, usize> = BTreeMap::new();

        for (target_id, accusers) in self.complains.iter() {
            if accusers.len() * 3 > self.pub_keys.len() * 2 {
                let _ = failings.insert(target_id.clone());
                for peer in self.pub_keys.iter() {
                    if !accusers.contains(peer) {
                        *counting.entry(peer.clone()).or_insert(0usize) += 1;
                    }
                }
            }
        }
        for (peer, times) in counting {
            if times > self.pub_keys.len() / 2 {
                let _ = failings.insert(peer);
            }
        }
        failings
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
///   d, call `finalize_complain` to complete the complain phase. (This separate call may need to
///      depend on a separate timer & checker against the key generator's current status)
///   e, repeat step c when there is incoming `DkgMessage`.
///   f, call `generate` to get the public-key set and secret-key share, if the procedure finalized.
pub struct KeyGen<S: SecretId> {
    /// Our node ID.
    our_id: S::PublicId,
    /// Our node index.
    our_idx: u64,
    /// The public keys of all nodes, by node ID.
    pub_keys: BTreeSet<S::PublicId>,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
    /// Current DKG phase.
    dkg_phase: DkgPhases,
    /// Accumulates initializations.
    acc_initial: AccumulateInitial<S::PublicId>,
    /// Accumulates contributes.
    acc_contribute: AccumulateContribute<S::PublicId>,
    /// Accumulates Complains.
    acc_complain: AccumulateComplain<S::PublicId>,
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
        let our_idx = if let Some(idx) = pub_keys.iter().position(|id| *id == our_id) {
            idx as u64
        } else {
            return Err(Error::Unknown);
        };

        let key_gen = KeyGen::<S> {
            our_id,
            our_idx,
            pub_keys: pub_keys.clone(),
            parts: BTreeMap::new(),
            threshold,
            dkg_phase: DkgPhases::Initial,
            acc_initial: AccumulateInitial::new(),
            acc_contribute: AccumulateContribute::new(pub_keys.clone()),
            acc_complain: AccumulateComplain::new(pub_keys.clone()),
        };

        Ok((
            key_gen,
            DkgMessage::Initial {
                key_gen_id: our_idx,
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
            DkgMessage::Initial {
                key_gen_id,
                m,
                n,
                member_list,
            } => self.handle_initialize(sec_key, rng, m, n, key_gen_id, member_list),

            DkgMessage::Contribution { key_gen_id, part } => {
                self.handle_contribute(sec_key, rng, key_gen_id, part)
            }
            DkgMessage::Complain {
                key_gen_id,
                target,
                msg,
            } => self.handle_complain(sec_key, key_gen_id, target, msg),
            DkgMessage::Justification { key_gen_id, part } => {
                self.handle_justificate(sec_key, key_gen_id, part)
            }
            DkgMessage::Commitment { key_gen_id, commit } => {
                if let Err(err) = self.handle_commit(sec_key, key_gen_id, commit) {
                    Err(err)
                } else {
                    Ok(None)
                }
            }
        }
    }

    // Handles an incoming initialize message. Creates the `Contribute` message once quorumn
    // agreement reached, and the message should be multicast to all nodes.
    fn handle_initialize(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
        m: usize,
        n: usize,
        sender: u64,
        member_list: BTreeSet<S::PublicId>,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Initial {
            return Err(Error::Unknown);
        }
        if let Some((m, n, member_list)) = self.acc_initial.add_initial(m, n, sender, member_list) {
            self.threshold = m;
            self.pub_keys = member_list;
            self.dkg_phase = DkgPhases::Contribute;

            let mut rng = rng_adapter::RngAdapter(&mut *rng);
            let our_part = BivarPoly::random(self.threshold, &mut rng);
            let commit = our_part.commitment();
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
                key_gen_id: self.our_idx,
                part: Part(commit, rows),
            });
            return Ok(Some(result));
        }
        Ok(None)
    }

    // Handles a `Contribute` message.
    // If it is invalid, sends a `Complain` message targeting the sender to be broadcast.
    // If all contributed, retuns a `Commitment` message to be broadcast.
    fn handle_contribute(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
        sender_idx: u64,
        part: Part,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Contribute {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_idx)
            .ok_or(Error::UnknownSender)?;

        if !self
            .acc_contribute
            .add_contribute(sender_id, sender_idx, part)
        {
            return Ok(None);
        }

        self.dkg_phase = DkgPhases::Complain;

        let mut msgs = Vec::new();
        for ((sender_id, sender_idx), part) in self.acc_contribute.contributes.clone() {
            match self.handle_part_or_fault(sec_key, sender_idx, &sender_id, part.clone()) {
                Ok(Some(_row)) => {}
                Ok(None) => {}
                Err(_fault) => {
                    let msg = DkgMessage::Contribution::<S::PublicId> {
                        key_gen_id: sender_idx,
                        part,
                    };
                    let invalid_contribute = serialisation::serialise(&msg)?;
                    msgs.push(DkgMessage::Complain {
                        key_gen_id: self.our_idx,
                        target: sender_idx,
                        msg: invalid_contribute,
                    });
                }
            }
        }

        // In case of no complains, calling finalize_complain to jump to `Justification` state.
        // FIXME: May still be needed to be in `Complain` state, as others may complain?
        if msgs.is_empty() {
            if let Ok(msg) = self.finalize_complain(sec_key, rng) {
                msgs.push(msg);
            } else {
                return Err(Error::Unknown);
            }
        }

        Ok(Some(msgs))
    }

    // Handles a `Complain` message.
    fn handle_complain(
        &mut self,
        sec_key: &S,
        sender_idx: u64,
        target_idx: u64,
        invalid_msg: Vec<u8>,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Complain {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_idx)
            .ok_or(Error::UnknownSender)?;
        let target_id = self.node_id_from_index(target_idx).ok_or(Error::Unknown)?;

        self.acc_complain
            .add_complain(sender_id, target_id, invalid_msg);
        Ok(None)
    }

    // TODO: so far this function has to be called externally to indicates a completion of complain
    //       phase. May need to be further verified whether there is a better approach.
    pub fn finalize_complain(
        &mut self,
        sec_key: &S,
        rng: &mut dyn rand::Rng,
    ) -> Result<DkgMessage<S::PublicId>, Error> {
        let failings = self.acc_complain.finalize_complain();
        if !failings.is_empty() {
            for failing in failings.iter() {
                let _ = self.pub_keys.remove(failing);
            }
            self.our_idx = self.node_index(&self.our_id).ok_or(Error::Unknown)?;
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
            key_gen_id: self.our_idx,
            part: Part(justify, rows),
        })
    }

    // Handles a `Justification` message.
    fn handle_justificate(
        &mut self,
        sec_key: &S,
        sender_idx: u64,
        part: Part,
    ) -> Result<Option<Vec<DkgMessage<S::PublicId>>>, Error> {
        if self.dkg_phase != DkgPhases::Justification {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_idx)
            .ok_or(Error::UnknownSender)?;
        let row = match self.handle_part_or_fault(sec_key, sender_idx, &sender_id, part) {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(None),
            Err(_fault) => {
                // FIXME: shall we return back to complain phase ?
                return Ok(None);
            }
        };
        // The row is valid. Encrypt one value for each node and broadcast a `Commitment`.
        let mut values = Vec::new();
        for (idx, pk) in self.pub_keys.iter().enumerate() {
            let val = row.evaluate(idx + 1);
            let ser_val = serialisation::serialise(&FieldWrap(val))?;
            values.push(sec_key.encrypt(pk, ser_val).ok_or(Error::Encryption)?);
        }
        self.dkg_phase = DkgPhases::Commitment;
        let mut result = Vec::new();
        result.push(DkgMessage::Commitment {
            key_gen_id: self.our_idx,
            commit: Commit(sender_idx, values),
        });
        Ok(Some(result))
    }

    // Handles a `Commit` message.
    fn handle_commit(
        &mut self,
        sec_key: &S,
        sender_idx: u64,
        commit: Commit,
    ) -> Result<CommitOutcome, Error> {
        if self.dkg_phase != DkgPhases::Commitment {
            return Err(Error::Unknown);
        }

        let sender_id = self
            .node_id_from_index(sender_idx)
            .ok_or(Error::UnknownSender)?;

        Ok(
            match self.handle_commit_or_fault(sec_key, &sender_id, sender_idx, commit) {
                Ok(()) => {
                    if self.is_ready() {
                        self.dkg_phase = DkgPhases::Finalize;
                    }
                    CommitOutcome::Valid
                }
                Err(fault) => CommitOutcome::Invalid(fault),
            },
        )
    }

    /// Returns the index of the node, or `None` if it is unknown.
    fn node_index(&self, node_id: &S::PublicId) -> Option<u64> {
        self.pub_keys
            .iter()
            .position(|id| id == node_id)
            .map(|idx| idx as u64)
    }

    /// Returns the id of the index, or `None` if it is unknown.
    fn node_id_from_index(&self, node_idx: u64) -> Option<S::PublicId> {
        for (i, pk) in self.pub_keys.iter().enumerate() {
            if i == node_idx as usize {
                return Some(pk.clone());
            }
        }
        None
    }

    /// Returns the number of complete parts. If this is at least `threshold + 1`, the keys can
    /// be generated, but it is possible to wait for more to increase security.
    fn count_complete(&self) -> usize {
        self.parts
            .values()
            .filter(|part| part.is_complete(self.threshold))
            .count()
    }

    /// Returns `true` if enough parts are complete to safely generate the new key.
    fn is_ready(&self) -> bool {
        self.count_complete() > self.threshold
    }

    /// Returns the new secret key share and the public key set.
    pub fn generate(&self) -> Result<(BTreeSet<S::PublicId>, DkgResult), Error> {
        if self.dkg_phase != DkgPhases::Finalize {
            return Err(Error::Unknown);
        }

        let mut pk_commit = Poly::zero().commitment();
        let mut sk_val = Fr::zero();
        let is_complete = |part: &&ProposalState| part.is_complete(self.threshold);
        for part in self.parts.values().filter(is_complete) {
            pk_commit += part.commit.row(0);
            let row = Poly::interpolate(part.values.iter().take(self.threshold + 1));
            sk_val.add_assign(&row.evaluate(0));
        }
        let sk = SecretKeyShare::from_mut(&mut sk_val);
        Ok((self.pub_keys.clone(), DkgResult::new(pk_commit.into(), sk)))
    }

    /// Handles a `Part`, returns a `PartFault` if it is invalid.
    fn handle_part_or_fault(
        &mut self,
        sec_key: &S,
        sender_idx: u64,
        sender_id: &S::PublicId,
        Part(commit, rows): Part,
    ) -> Result<Option<Poly>, PartFault> {
        if rows.len() != self.pub_keys.len() {
            return Err(PartFault::RowCount);
        }
        if let Some(state) = self.parts.get(&sender_idx) {
            if state.commit != commit {
                return Err(PartFault::MultipleParts);
            }
            return Ok(None); // We already handled this `Part` before.
        }
        let commit_row = commit.row(self.our_idx + 1);
        // Retrieve our own row's commitment, and store the full commitment.
        let _ = self.parts.insert(sender_idx, ProposalState::new(commit));
        // We are a validator: Decrypt and deserialize our row and compare it to the commitment.
        let ser_row = sec_key
            .decrypt(sender_id, &rows[self.our_idx as usize])
            .ok_or(PartFault::DecryptRow)?;
        let row: Poly =
            serialisation::deserialise(&ser_row).map_err(|_| PartFault::DeserializeRow)?;
        if row.commitment() != commit_row {
            return Err(PartFault::RowCommitment);
        }
        Ok(Some(row))
    }

    /// Handles a `Commit` message.
    fn handle_commit_or_fault(
        &mut self,
        sec_key: &S,
        sender_id: &S::PublicId,
        sender_idx: u64,
        Commit(proposer_idx, values): Commit,
    ) -> Result<(), CommitFault> {
        if values.len() != self.pub_keys.len() {
            return Err(CommitFault::ValueCount);
        }
        let part = self
            .parts
            .get_mut(&proposer_idx)
            .ok_or(CommitFault::MissingPart)?;
        if !part.commits.insert(sender_idx) {
            return Ok(()); // We already handled this `Commit` before.
        }
        let our_idx = self.our_idx;
        // We are a validator: Decrypt and deserialize our value and compare it to the commitment.
        let ser_val = sec_key
            .decrypt(sender_id, &values[our_idx as usize])
            .ok_or(CommitFault::DecryptValue)?;
        let val = serialisation::deserialise::<FieldWrap<Fr>>(&ser_val)
            .map_err(|_| CommitFault::DeserializeValue)?
            .into_inner();
        if part.commit.evaluate(our_idx + 1, sender_idx + 1) != G1Affine::one().mul(val) {
            return Err(CommitFault::ValueCommitment);
        }
        let _ = part.values.insert(sender_idx + 1, val);
        Ok(())
    }
}

// https://github.com/rust-lang/rust/issues/52560
// Cannot derive Debug without changing the type parameter
impl<S: SecretId> Debug for KeyGen<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "KeyGen{{our_id:{:?}, our_idx:{:?}, pub_keys :{:?}, parts:{:?}, threshold:{:?}}}",
            self.our_id, self.our_idx, self.pub_keys, self.parts, self.threshold
        )
    }
}

/// `Commit` faulty entries.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Fail, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CommitFault {
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
