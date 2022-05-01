// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]

#[cfg(test)]
extern crate serde_derive;
#[macro_use]
extern crate log;

pub mod key_gen;
pub use key_gen::*;

// export these because they are used in our public API.
pub use blsttc;
pub use rand_core;
pub use xor_name;

#[cfg(test)]
mod dev_utils;
