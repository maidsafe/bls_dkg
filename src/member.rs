// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::{PublicId as TraitPublicId, SecretId};
use crate::key_gen::message::Message;
use crate::key_gen::outcome::Outcome;
use crate::key_gen::{Error, KeyGen, Phase};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use crossbeam_channel::after;
use futures::lock::Mutex;
use log::trace;
use quic_p2p::{Config, Connection, Endpoint, QuicP2p};
use rand::{thread_rng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Time to wait before starting `timed_phase_transition` in milliseconds
pub const WAITING_TIME: u64 = 120_000; // 2 minutes - max time for a session with 7 Members to finish exchanging Contribution messages

/// Signing and verification.
pub mod signing {
    pub use threshold_crypto::{PublicKey, SecretKey, Signature, SIG_SIZE};
}

/// Encryption and decryption
pub mod encryption {
    pub use ed25519_dalek::{PublicKey, SecretKey};
}

/// A standalone object that can take start and/or take part in a BLS-DKG Session with Quic-p2p as it's transport layer.
pub struct Member {
    quic_p2p: QuicP2p,
    end_point: Endpoint,
    _id: u64,
    group: HashMap<NodeID, SocketAddr>,
    connections: HashMap<NodeID, Arc<Mutex<Connection>>>,
    key_gen: Option<KeyGen<KeyInfo>>,
    our_keys: KeyInfo,
    non_responsive: bool,
}

impl Member {
    /// Setup a Member to start DKG
    pub fn new<R: RngCore>(config: Config, rng: &mut R) -> Result<Self, Error> {
        let node = KeyInfo::new();

        let quic_p2p = QuicP2p::with_config(Some(config), VecDeque::new(), false)
            .map_err(|e| Error::QuicP2P(format!("{:#?}", e)))?;

        let end_point = quic_p2p
            .new_endpoint()
            .map_err(|e| Error::QuicP2P(format!("{:#?}", e)))?;

        Ok(Self {
            quic_p2p,
            end_point,
            _id: rng.gen(),
            group: Default::default(),
            connections: Default::default(),
            key_gen: None,
            our_keys: node,
            non_responsive: false,
        })
    }

    /// Connects to every member in the given group
    pub async fn connect_to_group(
        &mut self,
        group: HashMap<NodeID, SocketAddr>,
    ) -> Result<(), Error> {
        // Required to for testing network churns
        #[cfg(test)]
        self.disconnect_from_all().await;

        self.group = group;

        for (id, socket_addr) in self.group.iter() {
            println!("Trying to connect");
            let (_, connection) = self
                .quic_p2p
                .connect_to(socket_addr)
                .await
                .map_err(|e| Error::QuicP2P(e.to_string()))?;
            println!("CONNECTED!");
            let _ = self
                .connections
                .insert(id.clone(), Arc::new(Mutex::new(connection)));
        }

        Ok(())
    }

    /// Initialize DKG with the connected nodes and returns back the proposal
    pub fn init_dkg(&mut self, threshold: usize) -> Result<Message<NodeID>, Error> {
        // Extract public_keys of the nodes from the given group for DKG
        let pub_keys = self.group.keys().fold(BTreeSet::new(), |mut set, key| {
            let _ = set.insert(key.clone());
            set
        });

        // Initialize DKG
        let (key_gen, broadcast_msg) = KeyGen::initialize(&self.our_keys, threshold, pub_keys)?;

        self.key_gen = Some(key_gen);
        Ok(broadcast_msg)
    }

    /// Broadcast given message to all the connected peers
    pub async fn broadcast(&mut self, message: Message<NodeID>) -> Result<(), Error> {
        let mut tasks = Vec::default();
        for conn in self.connections.values() {
            let serialized_msg =
                serialize(&message).map_err(|e| Error::Serialization(e.to_string()))?;
            let bytes = Bytes::from(serialized_msg);
            let msg = bytes.clone();
            let conn = Arc::clone(conn);
            let task_handle = tokio::spawn(async move { conn.lock().await.send_only(msg).await });
            tasks.push(task_handle);
        }
        let _result = futures::future::join_all(tasks).await;
        Ok(())
    }

    /// Begins timed phase transition
    pub fn start_timed_phase_transition(&mut self) -> Result<Vec<Message<NodeID>>, Error> {
        let (tx, rx) = channel();
        let _ = thread::spawn(move || {
            #[cfg(not(test))]
            let ticker = after(Duration::from_millis(WAITING_TIME)); // 2 minutes

            // We don't have to wait in tests as we wait for completion of message exchanges beforehand
            #[cfg(test)]
            let ticker = after(Duration::from_millis(1_000)); // 1 second
            {
                ticker.recv().unwrap();
                tx.send(()).unwrap()
            }
        });
        rx.recv().unwrap();
        let mut rng = thread_rng();
        match self.key_gen {
            Some(ref mut key_gen) => key_gen.timed_phase_transition(&mut rng),
            None => Err(Error::QuicP2P("Keygen instance not found".to_string())),
        }
    }

    /// Fetches our NodeID
    pub fn id(&self) -> NodeID {
        self.our_keys.node_id()
    }

    /// Check if our node is ready to generate Keys safely
    pub fn is_ready(&self) -> Result<bool, Error> {
        if let Some(ref key_gen) = self.key_gen {
            Ok(key_gen.is_finalized())
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    /// Terminate the QUIC connections gracefully.
    pub async fn close(&mut self) {
        for (_, conn) in self.connections.iter_mut() {
            conn.lock().await.close()
        }
    }

    /// Generate keys from the key_gen
    pub fn generate_keys(&self) -> Result<(BTreeSet<NodeID>, Outcome), Error> {
        if let Some(ref key_gen) = self.key_gen {
            match key_gen.generate_keys() {
                Some(oc) => Ok(oc),
                None => Err(Error::QuicP2P("DKG DID NOT FINISH".to_string())),
            }
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    /// Returns the Phase the Node is at.
    pub fn phase(&self) -> Result<Phase, Error> {
        if let Some(ref key_gen) = self.key_gen {
            Ok(key_gen.phase())
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    // Dispatches the incoming DKG message to the Key_Gen instance
    pub async fn handle_incoming(&mut self, incoming: Vec<Bytes>) -> Vec<Message<NodeID>> {
        let mut replies = vec![];
        for message in incoming {
            match deserialize(&message) {
                Ok(msg) => {
                    let mut rng = thread_rng();
                    if let Some(ref mut key_gen) = self.key_gen {
                        match key_gen.handle_message(&mut rng, msg) {
                            Ok(list) => {
                                if !self.non_responsive {
                                    for message in list {
                                        // Broadcast the reply messages right away
                                        replies.push(message);
                                    }
                                }
                            }
                            Err(e) => trace!("Error: {:#?}", e),
                        }
                    } else {
                        trace!("Error: No Keygen instance initiated")
                    }
                }
                Err(e) => trace!("Error: {:#?}", e),
            }
        }
        replies
    }
}

#[cfg(test)]
impl Member {
    /// Check if our node has received all contributions
    pub fn all_contribution_received(&self) -> Result<bool, Error> {
        if let Some(ref key_gen) = self.key_gen {
            Ok(key_gen.all_contribution_received())
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    /// Fetches our quic connection's socket address
    pub fn our_socket_addr(&self) -> SocketAddr {
        self.end_point.local_address()
    }

    /// Set the given node as non_responsive
    pub fn set_as_non_responsive(&mut self) {
        self.non_responsive = true
    }

    /// Check if the node is non_responsive
    pub fn is_non_responsive(&self) -> bool {
        self.non_responsive
    }

    /// Disconnect from all the nodes
    pub async fn disconnect_from_all(&mut self) {
        for conn in self.connections.values() {
            conn.lock().await.close()
        }
    }
}

impl Ord for Member {
    fn cmp(&self, other: &Self) -> Ordering {
        self.our_keys.node_id().cmp(&other.our_keys.public_id)
    }
}

impl Eq for Member {}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.our_keys.node_id().eq(&other.our_keys.node_id())
    }
}

impl PartialOrd for Member {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.our_keys
            .node_id()
            .partial_cmp(&other.our_keys.node_id())
    }
}

#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct NodeID {
    name: String, // TODO: To be replaced by XorName?
    signing_key: signing::PublicKey,
    _encryption_key: encryption::PublicKey,
}

struct SecretKeys {
    _signing_keys: signing::SecretKey,
    _encryption_keys: encryption::SecretKey,
}

pub struct KeyInfo {
    public_id: NodeID,
    _secret_keys: SecretKeys,
}

impl KeyInfo {
    pub fn new() -> Self {
        let signing_secret_key = signing::SecretKey::random();
        let signing_public_key = signing_secret_key.public_key();

        let mut rng = thread_rng();
        let encryption_secret_key = encryption::SecretKey::generate(&mut rng);
        let encryption_public_key = encryption::PublicKey::from(&encryption_secret_key);

        let _secret_keys = SecretKeys {
            _signing_keys: signing_secret_key,
            _encryption_keys: encryption_secret_key,
        };

        let random_numb: u8 = thread_rng().gen();

        let public_id = NodeID {
            name: format!("NODE ID: {:#?}", random_numb),
            signing_key: signing_public_key,
            _encryption_key: encryption_public_key,
        };

        KeyInfo {
            public_id,
            _secret_keys,
        }
    }

    pub fn node_id(&self) -> NodeID {
        self.public_id.clone()
    }
}

impl TraitPublicId for NodeID {
    type Signature = signing::Signature;

    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.signing_key.verify(signature, data)
    }
}

impl SecretId for KeyInfo {
    type PublicId = NodeID;

    fn public_id(&self) -> &Self::PublicId {
        &self.public_id
    }
}

impl Default for KeyInfo {
    fn default() -> Self {
        Self::new()
    }
}
