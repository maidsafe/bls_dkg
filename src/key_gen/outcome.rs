// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use std::fmt::{self, Debug, Formatter};

use crate::{PublicKeySet, SecretKeyShare};

#[derive(Clone)]
/// DKG result
pub struct Outcome {
    /// Public key set to verify threshold signatures
    pub public_key_set: PublicKeySet,
    /// Secret Key share.
    pub secret_key_share: SecretKeyShare,
    /// Our index in the group
    pub index: usize,
}

impl Outcome {
    /// Create Outcome from components
    pub fn new(
        public_key_set: PublicKeySet,
        secret_key_share: SecretKeyShare,
        index: usize,
    ) -> Self {
        Self {
            public_key_set,
            secret_key_share,
            index,
        }
    }
}

impl Debug for Outcome {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Outcome({:?}, {:?}, {:?})",
            self.public_key_set, self.secret_key_share, self.index
        )
    }
}
