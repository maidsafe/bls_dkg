// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

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
