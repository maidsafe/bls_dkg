// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

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
}
