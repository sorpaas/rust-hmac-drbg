#![no_std]

#[macro_use]
extern crate typenum;
extern crate digest;
extern crate generic_array;

use digest::{Input, BlockInput, FixedOutput};
use generic_array::{ArrayLength, GenericArray};
use typenum::Quot;
use typenum::consts::*;
use core::ops::Div;

pub struct HmacDrbg<D>
    where D: Input + BlockInput + FixedOutput + Default,
          D::BlockSize: ArrayLength<u8>,
          D::OutputSize: ArrayLength<u8>
{
    digest: D,
    k: GenericArray<u8, D::OutputSize>,
    v: GenericArray<u8, D::OutputSize>,
}

impl<D> HmacDrbg<D>
    where D: Input + BlockInput + FixedOutput + Default,
          D::BlockSize: ArrayLength<u8>,
          D::OutputSize: ArrayLength<u8>
{
    pub fn raw(
        digest: D,
        k: GenericArray<u8, D::OutputSize>,
        v: GenericArray<u8, D::OutputSize>
    ) -> Self {
        Self { digest, k, v }
    }

    pub fn k(&self) -> &GenericArray<u8, D::OutputSize> {
        &self.k
    }

    pub fn v(&self) -> &GenericArray<u8, D::OutputSize> {
        &self.v
    }
}
