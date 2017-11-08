extern crate hmac_drbg;
extern crate sha2;
extern crate generic_array;
extern crate hexutil;
extern crate typenum;

use hmac_drbg::*;
use sha2::Sha256;
use generic_array::GenericArray;
use hexutil::*;
use typenum::consts::*;

#[test]
fn test1_sha256() {
    let mut drbg = HmacDrbg::<Sha256>::new(
        "totally random0123456789".as_bytes(),
        "secret nonce".as_bytes(),
        "my drbg".as_bytes());
    assert_eq!(drbg.generate::<U32>(None).as_slice(), read_hex("018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a157").unwrap().as_slice());
}

#[test]
fn test2_sha256() {
    let mut drbg = HmacDrbg::<Sha256>::new(
        "totally random0123456789".as_bytes(),
        "secret nonce".as_bytes(),
        &[]);
    assert_eq!(drbg.generate::<U32>(None).as_slice(), read_hex("ed5d61ecf0ef38258e62f03bbb49f19f2cd07ba5145a840d83b134d5963b3633").unwrap().as_slice());
}

#[test]
fn reseeding() {
    let mut original = HmacDrbg::<Sha256>::new(
        "totally random string with many chars that I typed in agony".as_bytes(),
        "nonce".as_bytes(),
        "pers".as_bytes());
    let mut reseeded = HmacDrbg::<Sha256>::new(
        "totally random string with many chars that I typed in agony".as_bytes(),
        "nonce".as_bytes(),
        "pers".as_bytes());

    assert_eq!(original.generate::<U32>(None), reseeded.generate::<U32>(None));
    reseeded.reseed("another absolutely random string".as_bytes(), None);
    assert_ne!(original.generate::<U32>(None), reseeded.generate::<U32>(None));
}
