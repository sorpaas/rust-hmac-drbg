extern crate hmac_drbg;
extern crate sha2;
extern crate generic_array;
extern crate hexutil;

use hmac_drbg::*;
use sha2::Sha256;
use generic_array::GenericArray;
use hexutil::*;

#[test]
fn test1_sha256() {
    let mut drbg = HmacDrbg::<Sha256>::new(
        "totally random0123456789".as_bytes(),
        "secret nonce".as_bytes(),
        "my drbg".as_bytes());
    let mut res = [0u8; 32];
    drbg.generate(&mut res, None);
    assert_eq!(&res, read_hex("018ec5f8e08c41e5ac974eb129ac297c5388ee1864324fa13d9b15cf98d9a157").unwrap().as_slice());
}

#[test]
fn test2_sha256() {
    let mut drbg = HmacDrbg::<Sha256>::new(
        "totally random0123456789".as_bytes(),
        "secret nonce".as_bytes(),
        &[]);
    let mut res = [0u8; 32];
    drbg.generate(&mut res, None);
    assert_eq!(&res, read_hex("ed5d61ecf0ef38258e62f03bbb49f19f2cd07ba5145a840d83b134d5963b3633").unwrap().as_slice());
}
