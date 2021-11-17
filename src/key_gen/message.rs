// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::encryptor::{Iv, Key};
use super::{Acknowledgment, Part};
use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use tiny_keccak::{Hasher, Sha3};
use xor_name::XorName;

/// SHA3-256 hash digest.
type Digest256 = [u8; 32];

/// Messages used for running BLS DKG.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Message {
    Initialization {
        key_gen_id: u64,
        m: usize,
        n: usize,
        member_list: BTreeSet<XorName>,
    },
    Proposal {
        key_gen_id: u64,
        part: Part,
    },
    Complaint {
        key_gen_id: u64,
        target: u64,
        msg: Vec<u8>,
    },
    Justification {
        key_gen_id: u64,
        keys_map: BTreeMap<XorName, (Key, Iv)>,
    },
    Acknowledgment {
        key_gen_id: u64,
        ack: Acknowledgment,
    },
}

impl Message {
    // Creator of the message.
    pub fn creator(&self) -> u64 {
        match &*self {
            Message::Initialization { key_gen_id, .. }
            | Message::Proposal { key_gen_id, .. }
            | Message::Complaint { key_gen_id, .. }
            | Message::Justification { key_gen_id, .. }
            | Message::Acknowledgment { key_gen_id, .. } => *key_gen_id,
        }
    }

    // Identifier of the message.
    pub fn id(&self) -> XorName {
        let mut hasher = Sha3::v256();
        let mut hash = Digest256::default();

        if let Ok(serialized) = bincode::serialize(self) {
            hasher.update(&serialized);
            hasher.finalize(&mut hash);
        }

        XorName::from_content(&hash)
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            Message::Initialization {
                key_gen_id,
                member_list,
                ..
            } => write!(
                formatter,
                "Initialization({:?} - {:?})",
                member_list, key_gen_id
            ),
            Message::Proposal { key_gen_id, part } => {
                write!(formatter, "Proposal({} - {:?})", key_gen_id, part)
            }
            Message::Complaint {
                key_gen_id, target, ..
            } => write!(formatter, "Complaint({} - {})", key_gen_id, target),
            Message::Justification { key_gen_id, .. } => {
                write!(formatter, "Justification({})", key_gen_id)
            }
            Message::Acknowledgment { key_gen_id, ack } => {
                write!(formatter, "Acknowledgment({} - {:?})", key_gen_id, ack)
            }
        }
    }
}
