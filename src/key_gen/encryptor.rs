// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::Error;
use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use xor_name::XorName;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const KEY_SIZE: usize = 16;
const IV_SIZE: usize = 16;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Key(pub [u8; KEY_SIZE]);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Iv(pub [u8; IV_SIZE]);

fn encrypt(data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, Error> {
    let cipher = Aes128Cbc::new_from_slices(key.0.as_ref(), iv.0.as_ref())
        .map_err(|_e| Error::Encryption)?;
    Ok(cipher.encrypt_vec(data))
}

// pub fn decrypt(encrypted_data: &[u8], key: &Key, iv: &Iv) -> Result<Vec<u8>, Error> {
//     let cipher =
//         Aes128Cbc::new_from_slices(key.0.as_ref(), iv.0.as_ref()).map_err(|_err| Error::Encryption)?;
//     cipher
//         .decrypt_vec(encrypted_data)
//         .map_err(|_err| Error::Encryption)
// }

/// An instance holds the encryption keys during the DKG procedure, and provides the encryption
/// facilities.
pub struct Encryptor {
    keys_map: BTreeMap<XorName, (Key, Iv)>,
}

impl Encryptor {
    pub fn new(peers: &BTreeSet<XorName>) -> Self {
        let mut keys_map = BTreeMap::new();
        // let mut rng = rand::thread_rng();
        // let mut rng_adaptor = RngAdapter(&mut rng);
        for name in peers.iter() {
            let key = Key(rand::thread_rng().gen());
            let iv = Iv(rand::thread_rng().gen());
            let _ = keys_map.insert(*name, (key, iv));
        }
        Encryptor { keys_map }
    }

    pub fn encrypt<M: AsRef<[u8]>>(&self, to: &XorName, msg: M) -> Result<Vec<u8>, Error> {
        if let Some((key, iv)) = self.keys_map.get(to) {
            encrypt(msg.as_ref(), key, iv)
        } else {
            Err(Error::Encryption)
        }
    }

    pub fn keys_map(&self) -> BTreeMap<XorName, (Key, Iv)> {
        self.keys_map.clone()
    }

    // pub fn decrypt(&self, from: &P, ct: &[u8]) -> Result<Vec<u8>, Error> {
    //     if let Some((key, iv)) = self.keys_map.get(from) {
    //         decrypt(ct, key, iv)
    //     } else {
    //         Err(Error::Encryption)
    //     }
    // }
}
