#![no_std]

#[macro_use]
extern crate typenum;
extern crate hmac_drbg;
extern crate sha2;
extern crate generic_array;

use hmac_drbg::*;
use sha2::Sha256;
use generic_array::GenericArray;

#[test]
fn generic_array_size() {
    let drbg = HmacDrbg::<Sha256>::raw(Sha256::default(), GenericArray::default(), GenericArray::default());
    assert_eq!(drbg.k().as_slice().len(), 256 / 8);
    assert_eq!(drbg.v().as_slice().len(), 256 / 8);
}
