// Copyright (c) 2022, MaidSafe.
// All rights reserved.
//
// This SAFE Network Software is licensed under the BSD-3-Clause license.
// Please see the LICENSE file for more details.

use rand::Rng;
use rand_core::RngCore;

pub(super) struct RngAdapter<'a, T: ?Sized>(pub &'a mut T);

impl<'a, T> RngCore for RngAdapter<'a, T>
where
    T: Rng + ?Sized,
{
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }

    #[inline]
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill_bytes(bytes);
        Ok(())
    }
}
