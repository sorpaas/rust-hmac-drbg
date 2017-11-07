#![no_std]

extern crate hmac_drbg;
extern crate sha2;
extern crate generic_array;

use hmac_drbg::*;
use sha2::Sha256;
use generic_array::GenericArray;
