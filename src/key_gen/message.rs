// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{Commitment, Part};
use crate::id::PublicId;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// Messages used for running BLS DKG.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Message<P: PublicId> {
    Initialization {
        key_gen_id: u64,
        m: usize,
        n: usize,
        member_list: BTreeSet<P>,
    },
    Contribution {
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
        part: Part,
    },
    Commitment {
        key_gen_id: u64,
        commitment: Commitment,
    },
}

impl<P: PublicId> fmt::Debug for Message<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Message::Initialization { key_gen_id, .. } => {
                write!(formatter, "Initialization({})", key_gen_id)
            }
            Message::Contribution { key_gen_id, .. } => {
                write!(formatter, "Contribution({})", key_gen_id)
            }
            Message::Complaint { key_gen_id, .. } => write!(formatter, "Complaint({})", key_gen_id),
            Message::Justification { key_gen_id, .. } => {
                write!(formatter, "Justification({})", key_gen_id)
            }
            Message::Commitment { key_gen_id, .. } => {
                write!(formatter, "Commitment({})", key_gen_id)
            }
        }
    }
}
