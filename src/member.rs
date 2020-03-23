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
use crate::key_gen::{Error, KeyGen};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use crossbeam_channel::{unbounded, Receiver};
use log::{info, trace};
use quic_p2p::{Builder, Config, Event, Peer, QuicP2p, QuicP2pError, Token};
use rand::{thread_rng, Rng};
use schedule_recv::periodic_ms;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use threshold_crypto::Ciphertext;

pub struct Member {
    inner: Arc<Mutex<Inner>>,
}

impl Member {
    pub fn new(
        group: HashMap<NodeID, (SocketAddr, Peer)>,
        threshold: usize,
        config: Config,
    ) -> Result<Self, Error> {
        let node = Node::new();

        let (node_tx, node_rx) = unbounded::<Event>();
        let (client_tx, _client_rx) = unbounded();

        let quic_p2p = Builder::new(quic_p2p::EventSenders { node_tx, client_tx })
            .with_config(config)
            .build()
            .map_err(|e| Error::QuicP2P(format!("{:#?}", e)))?;

        let pub_keys = group.keys().fold(BTreeSet::new(), |mut set, key| {
            let _ = set.insert(key.clone());
            set
        });

        let (key_gen, broadcast_msg) = KeyGen::initialize(&node, threshold, pub_keys)?;
        let connected = group.iter().fold(HashMap::new(), |mut map, (_addr, peer)| {
            let _ = map.insert(peer.1.clone(), false);
            map
        });

        let inner = Inner {
            quic_p2p,
            id: 0,
            group,
            connected,
            key_gen,
            our_keys: node,
        };

        let arc_inner = Arc::new(Mutex::new(inner));

        broadcast_and_start_timer(&arc_inner, broadcast_msg);
        let _ = setup_quic_p2p_event_loop(&arc_inner, node_rx);

        Ok(Self { inner: arc_inner })
    }

    /// Terminate the QUIC connections gracefully.
    pub fn close(&mut self) {
        self.inner.lock().unwrap().close()
    }
}

#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct NodeID {
    name: String, // TODO: To be replaced by XorName?
    signing_key: signing::PublicKey,
    _encryption_key: encryption::PublicKey,
}

struct SecretKeys {
    signing_keys: signing::SecretKey,
    _encryption_keys: encryption::SecretKey,
}

struct Node {
    public_id: NodeID,
    secret_keys: SecretKeys,
}

impl Node {
    pub fn new() -> Self {
        let signing_secret_key = signing::SecretKey::random();
        let signing_public_key = signing_secret_key.public_key();

        let mut rng = thread_rng();
        let encryption_secret_key = encryption::SecretKey::generate(&mut rng);
        let encryption_public_key = encryption::PublicKey::from(&encryption_secret_key);

        let secret_keys = SecretKeys {
            signing_keys: signing_secret_key,
            _encryption_keys: encryption_secret_key,
        };

        let random_numb: u8 = thread_rng().gen();

        let public_id = NodeID {
            name: format!("NODE ID: {:#?}", random_numb),
            signing_key: signing_public_key,
            _encryption_key: encryption_public_key,
        };

        Node {
            public_id,
            secret_keys,
        }
    }
}

impl TraitPublicId for NodeID {
    type Signature = signing::Signature;

    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.signing_key.verify(signature, data)
    }
}

impl SecretId for Node {
    type PublicId = NodeID;

    fn public_id(&self) -> &Self::PublicId {
        &self.public_id
    }

    fn encrypt<M: AsRef<[u8]>>(&self, to: &Self::PublicId, msg: M) -> Option<Vec<u8>> {
        serialize(&to.signing_key.encrypt(msg)).ok()
    }

    fn decrypt(&self, _from: &Self::PublicId, ct: &[u8]) -> Option<Vec<u8>> {
        let ciphertext: Ciphertext = deserialize(ct).ok()?;
        self.secret_keys.signing_keys.decrypt(&ciphertext)
    }
}

struct Inner {
    quic_p2p: QuicP2p,
    id: u64,
    group: HashMap<NodeID, (SocketAddr, Peer)>,
    connected: HashMap<Peer, bool>,
    key_gen: KeyGen<Node>,
    our_keys: Node,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.terminate();
        thread::sleep(Duration::from_millis(50));
    }
}

impl Inner {
    pub fn connect_to_all(&mut self) {
        for member in self.group.iter() {
            let (socket_addr, _peer) = member.1;
            self.quic_p2p.connect_to(*socket_addr)
        }
    }

    pub fn handle_connected_to(&mut self, peer: Peer) {
        trace!("Connected to Peer: {:?}", peer);
        let _ = self.connected.insert(peer, true);
    }

    pub fn if_connected_to_all(&self) -> bool {
        self.connected.iter().all(|item| item.1 == &true)
    }

    fn handle_incoming(&mut self, msg: Bytes) {
        match deserialize(&msg) {
            Ok(msg) => {
                let mut rng = thread_rng();
                match self.key_gen.handle_message(&self.our_keys, &mut rng, msg) {
                    Ok(list) => {
                        for msg in list {
                            self.broadcast(msg)
                        }
                    }
                    Err(e) => trace!("Error: {:#?}", e),
                }
            }
            Err(e) => trace!("Error: {:#?}", e),
        }
    }

    fn broadcast(&mut self, message: Message<NodeID>) {
        for (_, (_socket_addr, peer)) in self.group.iter() {
            let token = rand::thread_rng().gen();
            let serialized_msg = serialize(&message).unwrap();
            let msg = Bytes::from(serialized_msg.as_slice());
            self.quic_p2p.send(peer.clone(), msg.clone(), token)
        }
    }

    fn start_timed_phase_trasition(&mut self) {
        let tick = periodic_ms(300_000); // 5 minutes

        loop {
            tick.recv().unwrap();
            let mut rng = thread_rng();
            let messages = self
                .key_gen
                .timed_phase_transition(&self.our_keys, &mut rng);
            match messages {
                Ok(list) => {
                    if list.is_empty() {
                        break;
                    } else {
                        for msg in list {
                            self.broadcast(msg)
                        }
                    }
                }
                Err(e) => {
                    trace!("Error: {:#?}", e);
                    break;
                }
            }
        }
    }

    fn terminate(&mut self) {
        for (_nodeid, (socket_addr, _peer)) in self.group.iter() {
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
            NewMessage { msg, .. } => {
                self.handle_incoming(msg);
            }
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
            self.connected.insert(peer, false);
        }
    }
}

fn broadcast_and_start_timer(inner: &Arc<Mutex<Inner>>, broadcast_msg: Message<NodeID>) {
    let inner_weak = Arc::downgrade(&inner);

    if let Some(inner) = inner_weak.upgrade() {
        let mut inner_locked = inner.lock().unwrap();
        inner_locked.connect_to_all();
        let mut connected = false;
        while !connected {
            connected = inner_locked.if_connected_to_all();
            if connected {
                inner_locked.broadcast(broadcast_msg.clone());
                inner_locked.start_timed_phase_trasition();
            }
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
                        // Start timer on an event occuring - would come out if there is nothing to send
                        inner.start_timed_phase_trasition();
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
