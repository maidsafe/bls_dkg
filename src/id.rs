// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, hash::Hash};

/// The public identity of a node.  It provides functionality to allow it to be used as an
/// asymmetric signing public key.
pub trait PublicId: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned + Debug {
    /// The signature type associated with the chosen asymmetric key scheme.
    type Signature: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned + Debug;
    /// Verifies `signature` against `data` using this `PublicId`.  Returns `true` if valid.
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool;
}

/// The secret identity of a node.  It provides functionality to allow it to be used as an
/// asymmetric signing secret key and to also yield the associated public identity.
pub trait SecretId {
    /// The associated public identity type.
    type PublicId: PublicId;

    /// Returns the associated public identity.
    fn public_id(&self) -> &Self::PublicId;

    /// Encrypts the message using own Rng to `to`
    fn encrypt<M: AsRef<[u8]>>(&self, to: &Self::PublicId, msg: M) -> Option<Vec<u8>>;
    /// Decrypt message from `from`.
    fn decrypt(&self, from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>>;
}
