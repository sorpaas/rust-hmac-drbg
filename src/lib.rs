//! A pure Rust, heapless [HMAC-DRBG](https://csrc.nist.gov/csrc/media/events/random-number-generation-workshop-2004/documents/hashblockcipherdrbg.pdf) implementation.
#![no_std]

use digest::{
    block_buffer::Eager,
    core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::typenum::{IsLess, Le, NonZero, U256},
    HashMarker, OutputSizeUser,
};
use generic_array::{ArrayLength, GenericArray};
use hmac::{Hmac, Mac};

/// An HMAC-based Deterministic Random Bit Generator.
pub struct HmacDRBG<D>
where
    D: CoreProxy,
    D::Core: Sync
        + HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    k: GenericArray<u8, <D::Core as OutputSizeUser>::OutputSize>,
    v: GenericArray<u8, <D::Core as OutputSizeUser>::OutputSize>,
    count: usize,
}

impl<D> HmacDRBG<D>
where
    D: CoreProxy,
    D::Core: Sync
        + HashMarker
        + UpdateCore
        + FixedOutputCore
        + BufferKindUser<BufferKind = Eager>
        + Default
        + Clone,
    <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The HMAC-DRBG constructor.
    ///
    /// # Parameters
    /// @entropy: The DRBG entropy seed.
    /// @nonce: A cryptographic nonce.
    /// @info: Additional input value
    pub fn new(entropy: &[u8], nonce: &[u8], info: &[u8]) -> Self {
        let mut k = GenericArray::<u8, <D::Core as OutputSizeUser>::OutputSize>::default();
        let mut v = GenericArray::<u8, <D::Core as OutputSizeUser>::OutputSize>::default();

        for i in 0..k.as_slice().len() {
            k[i] = 0x0;
        }

        for i in 0..v.as_slice().len() {
            v[i] = 0x01;
        }

        let mut this = Self { k, v, count: 0 };

        this.update(Some(&[entropy, nonce, info]));
        this.count = 1;

        this
    }

    /// The HMAC-DRBG update counter.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The HMAC-DRBG re-seeding function.
    pub fn reseed(&mut self, entropy: &[u8], add: Option<&[u8]>) {
        self.update(Some(&[entropy, add.unwrap_or(&[])]));
    }

    /// Generates the actual random bits into a GenericArray.
    pub fn generate<T: ArrayLength<u8>>(&mut self, add: Option<&[u8]>) -> GenericArray<u8, T> {
        let mut result = GenericArray::default();
        self.generate_to_slice(result.as_mut_slice(), add);
        result
    }

    /// Generates the actual random bits into a slice passed as the second argument.
    pub fn generate_to_slice(&mut self, result: &mut [u8], add: Option<&[u8]>) {
        if let Some(add) = add {
            self.update(Some(&[add]));
        }

        let mut i = 0;
        while i < result.len() {
            let mut vmac = self.hmac();
            vmac.update(&self.v);
            self.v = vmac.finalize().into_bytes();

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
        Hmac::new_from_slice(&self.k).expect("Smaller and larger key size are handled by default")
    }

    fn update(&mut self, seeds: Option<&[&[u8]]>) {
        let mut kmac = self.hmac();
        kmac.update(&self.v);
        kmac.update(&[0x00]);
        if let Some(seeds) = seeds {
            for seed in seeds {
                kmac.update(seed);
            }
        }
        self.k = kmac.finalize().into_bytes();

        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();

        if seeds.is_none() {
            return;
        }

        let seeds = seeds.unwrap();

        let mut kmac = self.hmac();
        kmac.update(&self.v);
        kmac.update(&[0x01]);
        for seed in seeds {
            kmac.update(seed);
        }
        self.k = kmac.finalize().into_bytes();

        let mut vmac = self.hmac();
        vmac.update(&self.v);
        self.v = vmac.finalize().into_bytes();
    }
}
