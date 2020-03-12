// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::fmt::{self, Debug, Formatter};
use threshold_crypto::{PublicKeySet, SecretKeyShare};

#[derive(Clone)]
/// DKG result
pub struct DkgResult {
    /// Public key set to verify threshold signatures
    pub public_key_set: PublicKeySet,
    /// Secret Key share.
    pub secret_key_share: SecretKeyShare,
}

impl DkgResult {
    /// Create DkgResult from components
    pub fn new(public_key_set: PublicKeySet, secret_key_share: SecretKeyShare) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }
}

impl Debug for DkgResult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "DkgResult({:?}, {:?})",
            self.public_key_set, self.secret_key_share
        )
    }
}
