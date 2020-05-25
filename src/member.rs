// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::crypto::{encryption, signing};
use crate::id::{PublicId as TraitPublicId, SecretId};
use crate::key_gen::message::Message;
use crate::key_gen::outcome::Outcome;
use crate::key_gen::{Error, KeyGen, Phase};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use crossbeam_channel::{unbounded, Receiver};
use log::{info, trace};
use quic_p2p::{Builder, Config, Event, Peer, QuicP2p, QuicP2pError, Token};
use rand::{thread_rng, Rng};
use schedule_recv::periodic_ms;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{btree_set::BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

pub const IP_LOCAL_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

pub struct Member {
    inner: Arc<Mutex<Inner>>,
}

impl Member {
    pub fn new(config: Config) -> Result<Self, Error> {
        let node = KeyInfo::new();

        let (node_tx, node_rx) = unbounded::<Event>();
        let (client_tx, _client_rx) = unbounded();

        let quic_p2p = Builder::new(quic_p2p::EventSenders { node_tx, client_tx })
            .with_config(config)
            .build()
            .map_err(|e| Error::QuicP2P(format!("{:#?}", e)))?;

        let mut rng = thread_rng();

        let inner = Inner {
            quic_p2p,
            id: rng.gen(),
            group: Default::default(),
            connected: Default::default(),
            key_gen: None,
            our_keys: node,
            non_responsive: false,
        };
        let arc_inner = Arc::new(Mutex::new(inner));

        let _ = setup_quic_p2p_event_loop(&arc_inner, node_rx);

        Ok(Self { inner: arc_inner })
    }

    pub fn init_dkg(
        &mut self,
        group: HashMap<NodeID, SocketAddr>,
        threshold: usize,
    ) -> Result<Message<NodeID>, Error> {
        let mut inner_locked = self.inner.lock().unwrap();

        #[cfg(test)]
        inner_locked.disconnect_from_all();

        inner_locked.group = group.clone();

        // Maintain the list of connected nodes
        let connected = group.iter().fold(HashMap::new(), |mut map, (_addr, peer)| {
            let _ = map.insert(peer.clone(), false);
            map
        });

        // Clear just incase we have any dead connections due to network churns
        inner_locked.connected.clear();

        for (peer, status) in connected {
            let _ = inner_locked.connected.entry(peer).or_insert(status);
        }

        // Extract public_keys of the nodes from the given group for DKG
        let pub_keys = group.keys().fold(BTreeSet::new(), |mut set, key| {
            let _ = set.insert(key.clone());
            set
        });

        // Initialize DKG
        let (key_gen, broadcast_msg) =
            KeyGen::initialize(&inner_locked.our_keys, threshold, pub_keys)?;

        inner_locked.key_gen = Some(key_gen);
        inner_locked.connect_to_all();
        Ok(broadcast_msg)
    }

    /// Query connection status to other peers - Returns true if connected to all, else false
    pub fn if_connected_to_all(&mut self) -> bool {
        self.inner.lock().unwrap().if_connected_to_all()
    }

    /// Broadcast given message to all the connected peers
    pub fn broadcast(&mut self, msg: Message<NodeID>) -> Result<(), Error> {
        self.inner.lock().unwrap().broadcast(msg)
    }

    /// Begins timed phase transition
    pub fn start_timed_phase_transition(&mut self) -> Result<Vec<Message<NodeID>>, Error> {
        self.inner.lock().unwrap().start_timed_phase_trasition()
    }

    /// Fetches our NodeID
    pub fn id(&self) -> NodeID {
        self.inner.clone().lock().unwrap().our_keys.node_id()
    }

    /// Check if our node has received all contributions
    pub fn all_contribution_received(&self) -> Result<bool, Error> {
        if let Some(ref key_gen) = self.inner.lock().unwrap().key_gen {
            Ok(key_gen.all_contribution_received())
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    /// Check if our node is ready to generate Keys safely
    pub fn is_ready(&self) -> Result<bool, Error> {
        if let Some(ref key_gen) = self.inner.lock().unwrap().key_gen {
            Ok(key_gen.is_ready())
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    /// Terminate the QUIC connections gracefully.
    pub fn close(&mut self) {
        self.inner.lock().unwrap().close()
    }

    /// Generate keys from the key_gen
    pub fn generate_keys(&self) -> Result<(BTreeSet<NodeID>, Outcome), Error> {
        if let Some(ref key_gen) = self.inner.lock().unwrap().key_gen {
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
        if let Some(ref key_gen) = self.inner.lock().unwrap().key_gen {
            Ok(key_gen.phase())
        } else {
            Err(Error::QuicP2P("NO DKG INSTANCE FOUND".to_string()))
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Result<(Self, SocketAddr, NodeID), Error> {
        let mut config = Config::default();
        config.ip = Some(IP_LOCAL_HOST);
        config.port = Some(0);

        let node = KeyInfo::new();

        let (node_tx, node_rx) = unbounded::<Event>();
        let (client_tx, _client_rx) = unbounded();

        let mut quic_p2p = Builder::new(quic_p2p::EventSenders { node_tx, client_tx })
            .with_config(config)
            .build()
            .map_err(|e| Error::QuicP2P(format!("{:#?}", e)))?;

        let info = quic_p2p.our_connection_info().unwrap();
        let node_id = node.node_id();
        let mut rng = thread_rng();

        let inner = Inner {
            quic_p2p,
            id: rng.gen(),
            group: Default::default(),
            connected: Default::default(),
            key_gen: None,
            our_keys: node,
            non_responsive: false,
        };
        let arc_inner = Arc::new(Mutex::new(inner));

        let _ = setup_quic_p2p_event_loop(&arc_inner, node_rx);

        Ok((Self { inner: arc_inner }, info, node_id))
    }

    #[cfg(test)]
    pub fn set_as_non_responsive(&mut self) {
        self.inner.lock().unwrap().non_responsive = true
    }

    #[cfg(test)]
    pub fn is_non_responsive(&self) -> bool {
        self.inner.lock().unwrap().non_responsive
    }
}

impl Ord for Member {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.lock().unwrap().cmp(&other.inner.lock().unwrap())
    }
}

impl Eq for Member {}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.inner.lock().unwrap().eq(&other.inner.lock().unwrap())
    }
}

impl PartialOrd for Member {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.inner
            .lock()
            .unwrap()
            .partial_cmp(&other.inner.lock().unwrap())
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

struct Inner {
    quic_p2p: QuicP2p,
    id: u64,
    group: HashMap<NodeID, SocketAddr>,
    connected: HashMap<SocketAddr, bool>,
    key_gen: Option<KeyGen<KeyInfo>>,
    our_keys: KeyInfo,
    non_responsive: bool,
}

impl PartialEq for Inner {
    fn eq(&self, other: &Self) -> bool {
        self.our_keys.public_id().eq(other.our_keys.public_id())
    }
}

impl Ord for Inner {
    fn cmp(&self, other: &Self) -> Ordering {
        self.our_keys.node_id().cmp(&other.our_keys.public_id)
    }
}

impl PartialOrd for Inner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.our_keys
            .public_id()
            .partial_cmp(other.our_keys.public_id())
    }
}

impl Eq for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        self.terminate();
        thread::sleep(Duration::from_millis(50));
    }
}

impl Inner {
    // Connects to every Node in the group
    pub fn connect_to_all(&mut self) {
        for (_id, socket_addr) in self.group.iter() {
            // Safe to unwrap
            let connected = self.connected.get(socket_addr).unwrap();
            if !connected {
                self.quic_p2p.connect_to(*socket_addr)
            }
        }
    }

    #[cfg(test)]
    // Disconnects from every Node in the group
    pub fn disconnect_from_all(&mut self) {
        for (_id, socket_addr) in self.group.iter() {
            // Safe to unwrap
            let connected = self.connected.get(socket_addr).unwrap();
            if *connected {
                self.quic_p2p.disconnect_from(*socket_addr)
            }
        }
    }

    // Updates the connected list if successfully connected at the transport layer
    pub fn handle_connected_to(&mut self, peer: Peer) {
        trace!("Connected to Peer: {:?}", peer);
        let _ = self.connected.insert(peer.peer_addr(), true);
    }

    // Checks if we are connected to all the nodes in the group
    pub fn if_connected_to_all(&mut self) -> bool {
        self.connected.iter().all(|item| *item.1)
    }

    // Dispatches the incoming DKG message to the Key_Gen instance
    fn handle_incoming(&mut self, msg: Bytes, _peer: Peer) {
        match deserialize(&msg) {
            Ok(msg) => {
                let mut rng = thread_rng();
                if let Some(ref mut key_gen) = self.key_gen {
                    match key_gen.handle_message(&mut rng, msg) {
                        Ok(list) => {
                            if !self.non_responsive {
                                for message in list {
                                    // Broadcast the reply messages right away
                                    let _ = self.broadcast(message);
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

    fn broadcast(&mut self, message: Message<NodeID>) -> Result<(), Error> {
        for (_, socket_addr) in self.group.iter() {
            let token = rand::thread_rng().gen();
            let serialized_msg =
                serialize(&message).map_err(|e| Error::Serialization(e.to_string()))?;
            let msg = Bytes::from(serialized_msg.as_slice());
            self.quic_p2p
                .send(Peer::Node(*socket_addr), msg.clone(), token)
        }
        Ok(())
    }

    // Timed Phase transition needs to be called if we do not finalize automatically
    fn start_timed_phase_trasition(&mut self) -> Result<Vec<Message<NodeID>>, Error> {
        let tick = periodic_ms(10_000); // 10 seconds

        tick.recv().unwrap();
        let mut rng = thread_rng();
        match self.key_gen {
            Some(ref mut key_gen) => key_gen.timed_phase_transition(&mut rng),
            None => Err(Error::QuicP2P("Keygen instance not found".to_string())),
        }
    }

    fn terminate(&mut self) {
        for (_nodeid, socket_addr) in self.group.iter() {
            self.quic_p2p.disconnect_from(*socket_addr);
        }
    }

    /// Terminate the QUIC connections gracefully.
    pub fn close(&mut self) {
        trace!("{}: Terminating connection", self.id);
        self.terminate()
    }

    fn handle_quic_p2p_event(&mut self, event: Event) {
        use Event::*;
        match event {
            BootstrapFailure => {
                panic!("Unexpected event: Bootstrap Failure!");
            }
            BootstrappedTo { .. } => {
                panic!("Unexpected event: BootstrappedTo!");
            }
            ConnectedTo { peer } => self.handle_connected_to(peer),
            SentUserMessage { peer, msg, token } => {
                self.handle_sent_user_message(peer.peer_addr(), msg, token)
            }
            UnsentUserMessage { peer, msg, token } => {
                self.handle_unsent_user_message(peer.peer_addr(), &msg, token)
            }
            NewMessage { peer, msg } => self.handle_incoming(msg, peer),
            Finish => {
                info!("Received unexpected event: {}", event);
            }
            ConnectionFailure { peer, err } => self.handle_connection_failure(peer, err),
        }
    }

    fn handle_sent_user_message(&mut self, _peer_addr: SocketAddr, _msg: Bytes, _token: Token) {
        trace!("{}: Sent user message", self.id);
    }

    fn handle_unsent_user_message(&mut self, _peer_addr: SocketAddr, _msg: &Bytes, _token: Token) {
        trace!("{}: User message not sent", self.id);
        // TODO: unimplemented
    }

    fn handle_connection_failure(&mut self, peer: Peer, err: QuicP2pError) {
        if let QuicP2pError::ConnectionCancelled = err {
            trace!(
                "{}: Recvd connection failure for {}, {}",
                self.id,
                peer,
                err
            );
            self.connected.insert(peer.peer_addr(), false);
        }
    }
}

fn setup_quic_p2p_event_loop(
    inner: &Arc<Mutex<Inner>>,
    event_rx: Receiver<Event>,
) -> JoinHandle<()> {
    let inner_weak = Arc::downgrade(inner);

    thread::spawn(move || {
        while let Ok(event) = event_rx.recv() {
            match event {
                Event::Finish => break, // Graceful shutdown
                event => {
                    if let Some(inner) = inner_weak.upgrade() {
                        let mut inner = inner.lock().unwrap();
                        inner.handle_quic_p2p_event(event);
                    } else {
                        // Event loop got dropped
                        trace!("Gracefully terminating quic-p2p event loop");
                        break;
                    }
                }
            }
        }
    })
}
