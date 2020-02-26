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

    /// Creates a detached `Signature` of `data`.
    fn sign_detached(&self, data: &[u8]) -> <Self::PublicId as PublicId>::Signature;

    /// Creates a `Proof` of `data`.
    fn create_proof(&self, data: &[u8]) -> Proof<Self::PublicId> {
        Proof {
            public_id: self.public_id().clone(),
            signature: self.sign_detached(data),
        }
    }

    /// Encrypts the message using own Rng to `to`
    fn encrypt<M: AsRef<[u8]>>(&self, to: &Self::PublicId, msg: M) -> Option<Vec<u8>>;
    /// Decrypt message from `from`.
    fn decrypt(&self, from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>>;
}

/// A basic helper to carry a given [`Signature`](trait.PublicId.html#associatedtype.Signature)
/// along with the signer's [`PublicId`](trait.PublicId.html).
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Proof<P: PublicId> {
    pub(super) public_id: P,
    pub(super) signature: P::Signature,
}

impl<P: PublicId> Proof<P> {
    /// Returns the associated public identity.
    pub fn public_id(&self) -> &P {
        &self.public_id
    }

    /// Returns the associated signature.
    pub fn signature(&self) -> &P::Signature {
        &self.signature
    }

    /// Verifies this `Proof` against `data`.  Returns `true` if valid.
    pub fn is_valid(&self, data: &[u8]) -> bool {
        self.public_id.verify_signature(&self.signature, data)
    }
}
