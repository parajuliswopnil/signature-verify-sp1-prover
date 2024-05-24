//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use keccak_hash::{self, keccak};
use hex_literal::hex;

pub fn main() {
    // NOTE: values of n larger than 186 will overflow the u128 type,
    // resulting in output that doesn't match fibonacci sequence.
    // However, the resulting proof will still be valid!
    let preimage = sp1_zkvm::io::read::<String>();
    
    let preimage_bt = preimage.as_bytes();
    let hash = keccak(preimage_bt);

    let signing_key = SigningKey::from_bytes(&hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").into()).unwrap();

    let signature: Signature = signing_key.sign(hash.as_bytes());

    let verifying_key = VerifyingKey::from(&signing_key);
    assert!(verifying_key.verify(hash.as_bytes(), &signature).is_ok());

    sp1_zkvm::io::commit(&signature.to_bytes().as_slice());
}
