// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Commitment, Part};
use crate::id::PublicId;
use std::collections::BTreeSet;
use std::fmt;

/// Messages used for running BLS DKG.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DkgMessage<P: PublicId> {
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

impl<P: PublicId> fmt::Debug for DkgMessage<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DkgMessage::Initialization { key_gen_id, .. } => {
                write!(formatter, "DkgInitialization({})", key_gen_id)
            }
            DkgMessage::Contribution { key_gen_id, .. } => {
                write!(formatter, "DkgContribution({})", key_gen_id)
            }
            DkgMessage::Complaint { key_gen_id, .. } => {
                write!(formatter, "DkgComplaint({})", key_gen_id)
            }
            DkgMessage::Justification { key_gen_id, .. } => {
                write!(formatter, "DkgJustification({})", key_gen_id)
            }
            DkgMessage::Commitment { key_gen_id, .. } => {
                write!(formatter, "DkgCommitment({})", key_gen_id)
            }
        }
    }
}
