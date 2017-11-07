#![no_std]

extern crate hmac;
extern crate digest;
extern crate generic_array;

use digest::{Input, BlockInput, FixedOutput};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Mac, Hmac, MacResult};

pub struct HmacDrbg<D>
    where D: Input + BlockInput + FixedOutput + Default,
          D::BlockSize: ArrayLength<u8>,
          D::OutputSize: ArrayLength<u8>
{
    digest: D,
    k: MacResult<D::OutputSize>,
    v: MacResult<D::OutputSize>,
}

impl<D> HmacDrbg<D>
    where D: Input + BlockInput + FixedOutput + Default,
          D::BlockSize: ArrayLength<u8>,
          D::OutputSize: ArrayLength<u8>
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
            digest: D::default(),
            k: MacResult::new(k),
            v: MacResult::new(v),
        };

        this.update(&[entropy, nonce, pers]);

        this
    }

    fn hmac(&self) -> Hmac<D> {
        Hmac::new(self.k.code())
    }

    fn update(&mut self, seeds: &[&[u8]]) {
        let mut kmac = self.hmac();
        kmac.input(self.v.code());
        kmac.input(&[0x00]);
        for seed in seeds {
            kmac.input(seed);
        }
        self.k = kmac.result();

        let mut vmac = self.hmac();
        vmac.input(self.v.code());
        self.v = vmac.result();

        let mut kmac = self.hmac();
        kmac.input(self.v.code());
        kmac.input(&[0x01]);
        for seed in seeds {
            kmac.input(seed);
        }
        self.k = kmac.result();

        let mut vmac = self.hmac();
        vmac.input(self.v.code());
        self.v = vmac.result();
    }
}
