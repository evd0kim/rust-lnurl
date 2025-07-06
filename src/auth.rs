extern crate hex;
extern crate secp256k1;

use secp256k1::hashes::{sha256, Hash};
use secp256k1::{ecdsa::Signature, Error, Message, PublicKey, Secp256k1, Verification, VerifyOnly};
use std::convert::TryInto;
use std::io::Read;

/// VerifierError is the AuthVerifier errors.
#[derive(Debug)]
pub enum VerifierError {
    Secp256k1Error(Error),
    HexError(hex::FromHexError),
}

/// AuthVerifier verifies the secp256k1 signature of a message with a given pubkey.
#[derive(Clone)]
pub struct AuthVerifier {
    secp: Secp256k1<VerifyOnly>,
}

impl AuthVerifier {
    pub fn new() -> Self {
        AuthVerifier {
            secp: Secp256k1::verification_only(),
        }
    }

    /// verifies the secp256k1 signature of a message with a given pubkey.
    pub fn verify(self, hk1: &str, hsig: &str, hpubkey: &str) -> Result<bool, VerifierError> {
        let msg = hex::decode(hk1).map_err(|e| VerifierError::HexError(e))?;
        let sig = hex::decode(hsig).map_err(|e| VerifierError::HexError(e))?;
        let pubkey = hex::decode(hpubkey).map_err(|e| VerifierError::HexError(e))?;
        let bytes: [u8; 32] = msg.try_into().expect("wrong length");
        verify_sig(&self.secp, &bytes, &sig, &pubkey).map_err(|e| VerifierError::Secp256k1Error(e))
    }
}

/// verify_sig checks if the signature of a key for a given message is valid.
pub fn verify_sig<C: Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8; 32],
    sig: &[u8],
    pubkey: &[u8],
) -> Result<bool, Error> {
    //let digest = sha256::Hash::hash(msg);
    //let message = Message::from_digest(digest.to_byte_array());
    let message = Message::from_digest(msg.to_owned());
    let sig = Signature::from_der(sig)?;
    let pubkey = PublicKey::from_slice(pubkey)?;
    secp.verify_ecdsa(message, &sig, &pubkey)?;
    Ok(true)
}
