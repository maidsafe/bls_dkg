// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::{PublicId, SecretId};
use rand::Rng;
use std::{
    cmp::Ordering,
    collections::hash_map::DefaultHasher,
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
};

pub const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
    "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina", "Ulf", "Vera", "Will",
    "Xaviera", "Yakov", "Zaida", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
];

lazy_static! {
    static ref PEERS: Vec<PeerId> = NAMES
        .iter()
        .map(|name| PeerId::new_with_keypair(name))
        .collect();
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerId {
    id: String,
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl PeerId {
    pub fn new(id: &str) -> Self {
        PEERS
            .iter()
            .find(|peer| peer.id == id)
            .cloned()
            .unwrap_or_else(|| PeerId::new_with_keypair(id))
    }

    fn new_with_keypair(id: &str) -> Self {
        let (public_key, secret_key) = gen_keypair();
        Self {
            id: id.to_owned(),
            public_key,
            secret_key,
        }
    }

    pub fn sec_key(&self) -> &Self {
        &self
    }
}

impl Debug for PeerId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.public_key.hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.id == other.id && self.public_key == other.public_key
    }
}

impl Eq for PeerId {}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &PeerId) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &PeerId) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PublicId for PeerId {
    type Signature = Signature;

    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        let mut hasher = DefaultHasher::new();
        hasher.write(data);
        hasher.write(&self.public_key.0);
        let hash = hasher.finish().to_le_bytes();

        signature.0[..hash.len()] == hash
    }
}

impl SecretId for PeerId {
    type PublicId = PeerId;

    fn public_id(&self) -> &Self::PublicId {
        &self
    }

    fn encrypt<M: AsRef<[u8]>>(&self, _to: &Self::PublicId, msg: M) -> Option<Vec<u8>> {
        // Pass through: We cannot store encryption keys as they are not reproductible.
        // This code is only used for test.
        Some(msg.as_ref().to_vec())
    }

    fn decrypt(&self, _from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>> {
        // Pass through: We cannot store encryption keys as they are not reproductible.
        // This code is only used for test.
        Some(ct.to_vec())
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    assert!(count <= NAMES.len());
    NAMES.iter().take(count).cloned().map(PeerId::new).collect()
}

const SIGNATURE_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;

// **NOT FOR PRODUCTION USE**: Mock public key.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PublicKey([u8; KEY_LENGTH]);

// **NOT FOR PRODUCTION USE**: Mock secret key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey([u8; KEY_LENGTH]);

// **NOT FOR PRODUCTION USE**: Mock signature.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Signature(..)")
    }
}

fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut rng = rand::thread_rng();
    let bytes: [u8; KEY_LENGTH] = rng.gen();
    (PublicKey(bytes), SecretKey(bytes))
}
