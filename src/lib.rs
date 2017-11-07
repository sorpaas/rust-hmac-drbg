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
          D::OutputSize: ArrayLength<u8>,
          D::OutputSize: Div<U8>,
          <D::OutputSize as Div<U8>>::Output: ArrayLength<u8>
{
    digest: D,
    k: GenericArray<u8, Quot<D::OutputSize, U8>>,
    v: GenericArray<u8, Quot<D::OutputSize, U8>>,
}
