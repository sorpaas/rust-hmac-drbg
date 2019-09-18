#![no_std]

pub use hmac::digest;
pub use hmac::digest::generic_array;

use hmac::digest::generic_array::{ArrayLength, GenericArray};
use hmac::digest::{BlockInput, FixedOutput, Input, Reset};
use hmac::{Hmac, Mac};

pub struct HmacDRBG<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    _digest: D,
    k: GenericArray<u8, D::OutputSize>,
    v: GenericArray<u8, D::OutputSize>,
    count: usize,
}

impl<D> HmacDRBG<D>
where
    D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    D::BlockSize: ArrayLength<u8>,
    D::OutputSize: ArrayLength<u8>,
{
    pub fn new(entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Self {
        let mut k = GenericArray::<u8, D::OutputSize>::default();
        let mut v = GenericArray::<u8, D::OutputSize>::default();

        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        for i in 0..v.as_slice().len() {
            v[i] = 0x01;
        }

        let mut this = Self {
            _digest: D::default(),
            k,
            v,
            count: 0,
        };

        this.update(Some(&[entropy, nonce, pers]));
        this.count = 1;

        this
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) {
        self.update(Some(&[entropy, add.unwrap_or(&[])]))
    }

    pub fn generate<T: ArrayLength<u8>>(&mut self, add: Option<&[u8]>) -> GenericArray<u8, T> {
        let mut result = GenericArray::default();
        self.generate_to_slice(result.as_mut_slice(), add);
        result
    }

    pub fn generate_to_slice(&mut self, result: &mut [u8], add: Option<&[u8]>) {
        if let Some(add) = add {
            self.update(Some(&[add]));
        }

        let mut i = 0;
        while i < result.len() {
            let mut vmac = self.hmac();
            vmac.input(&self.v);
            self.v = vmac.result().code();

            for j in 0..self.v.len() {
                result[i + j] = self.v[j];
            }
            i += self.v.len();
        }

        match add {
            Some(add) => {
                self.update(Some(&[add]));
            }
            None => {
                self.update(None);
            }
        }
        self.count += 1;
    }

    fn hmac(&self) -> Hmac<D> {
        Hmac::new_varkey(&self.k).expect("HMAC can take key of any size")
    }

    fn update(&mut self, seeds: Option<&[&[u8]]>) {
        if let Some(seeds) = seeds {
            // K = HMAC(K, V || 0x00 || input)
            let mut kmac = self.hmac();
            kmac.input(&self.v);
            kmac.input(&[0x00]);
            for seed in seeds {
                kmac.input(seed);
            }
            self.k = kmac.result().code();

            // V = HMAC(K, V)
            let mut vmac = self.hmac();
            vmac.input(&self.v);
            self.v = vmac.result().code();

            // K = HMAC(K, V || 0x01 || input)
            let mut kmac = self.hmac();
            kmac.input(&self.v);
            kmac.input(&[0x01]);
            for seed in seeds {
                kmac.input(seed);
            }
            self.k = kmac.result().code();

            // V = HMAC(K, V)
            let mut vmac = self.hmac();
            vmac.input(&self.v);
            self.v = vmac.result().code();
        } else {
            // K = HMAC(K, V || 0x00)
            let mut kmac = self.hmac();
            kmac.input(&self.v);
            kmac.input(&[0x00]);
            self.k = kmac.result().code();

            // V = HMAC(K, V)
            let mut vmac = self.hmac();
            vmac.input(&self.v);
            self.v = vmac.result().code();
        }
    }
}
