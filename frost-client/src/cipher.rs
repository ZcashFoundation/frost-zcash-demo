//! Handles encryption and decryption of messages, as well as signing
//! challenges, in order to use frostd to run FROST.

use std::collections::HashMap;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use snow::{HandshakeState, TransportState};
use thiserror::Error;
use xeddsa::{xed25519, Sign as _};
use zeroize::Zeroize;

use frostd::Msg;
pub use frostd::PublicKey;

/// Errors returned by this module.
#[derive(Error, Debug)]
pub enum Error {
    #[error("cryptography error from snow: {0}")]
    SnowError(#[from] snow::Error),
    #[error("unknown recipient")]
    UnkownRecipient,
    #[error("unknown sender")]
    UnkownSender,
    #[error("invalid private key")]
    InvalidPrivateKey,
}

/// A communication private key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Zeroize)]
#[serde(transparent)]
pub struct PrivateKey(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    Vec<u8>,
);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrivateKey").field(&"REDACTED").finish()
    }
}

impl TryFrom<PrivateKey> for xed25519::PrivateKey {
    type Error = Error;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        Ok(xed25519::PrivateKey::from(
            &TryInto::<[u8; 32]>::try_into(value.0).map_err(|_| Error::InvalidPrivateKey)?,
        ))
    }
}

impl From<Vec<u8>> for PrivateKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl PrivateKey {
    /// Sign a message by converting this key to a XED25519 key and signing
    /// with it.
    pub fn sign(&self, msg: &[u8], mut rng: impl RngCore + CryptoRng) -> Result<[u8; 64], Error> {
        let key: xed25519::PrivateKey = self.clone().try_into()?;
        Ok(key.sign(msg, &mut rng))
    }
}

/// A Noise state.
///
/// This abstracts away some awkwardness in the `snow` crate API, which
/// requires explicitly marking the handshake as finished and switching
/// to a new state object after the first message is sent.
struct Noise {
    // These should ideally be a enum, but that makes the implementation much
    // more awkward so I went with easier option which is using two Options.
    // Only one of them must has a value at any given time.
    /// The handshake state; None after handshake is complete.
    handshake_state: Option<HandshakeState>,
    /// The transport state; None before handshake is complete.
    transport_state: Option<TransportState>,
}

impl Noise {
    /// Create a new Noise state from a HandshakeState created with the `snow`
    /// crate.
    pub fn new(handshake_state: HandshakeState) -> Self {
        Self {
            handshake_state: Some(handshake_state),
            transport_state: None,
        }
    }

    /// Write (i.e. encrypts) a message following the same API as `snow`'s
    /// [`HandshakeState::write_message()`] and
    /// [`TransportState::write_message()`].
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        if let Some(handshake_state) = &mut self.handshake_state {
            // This does the handshake and also writes a first message.
            let r = handshake_state.write_message(payload, message);
            // This `if`` should always be true, we do the check regardless for safety.
            if handshake_state.is_handshake_finished() {
                // Get the transport state from the handshake state and update
                // the struct accordingly.
                let handshake_state = self
                    .handshake_state
                    .take()
                    .expect("there must be a handshake state set");
                self.transport_state = Some(handshake_state.into_transport_mode()?);
            }
            r
        } else if let Some(transport_state) = &mut self.transport_state {
            transport_state.write_message(payload, message)
        } else {
            panic!("invalid state");
        }
    }

    /// Reads (i.e. decrypts) a message following the same API as `snow`'s
    /// [`HandshakeState::read_message()`] and
    /// [`TransportState::read_message()`].
    pub fn read_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, snow::Error> {
        // See comments in [`Self::write_message()`].
        if let Some(handshake_state) = &mut self.handshake_state {
            let r = handshake_state.read_message(payload, message);
            if handshake_state.is_handshake_finished() {
                let handshake_state = self
                    .handshake_state
                    .take()
                    .expect("there must be a handshake state set");
                self.transport_state = Some(handshake_state.into_transport_mode()?);
            }
            r
        } else if let Some(transport_state) = &mut self.transport_state {
            transport_state.read_message(payload, message)
        } else {
            panic!("invalid state");
        }
    }
}

/// A cipher which can encrypt and decrypt messages.
pub struct Cipher {
    send_noise_map: HashMap<PublicKey, Noise>,
    recv_noise_map: HashMap<PublicKey, Noise>,
}

impl Cipher {
    /// Generate a keypair for use with this cipher.
    pub fn generate_keypair() -> Result<(PrivateKey, PublicKey), Error> {
        let builder = snow::Builder::new(
            "Noise_K_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .expect("should be a valid cipher"),
        );
        let keypair = builder.generate_keypair().map_err(Error::SnowError)?;
        Ok((PrivateKey(keypair.private), PublicKey(keypair.public)))
    }

    /// Instantiate a new cipher, with the user's private key and
    /// the public key of their peers.
    pub fn new(private_key: PrivateKey, peers_public_keys: Vec<PublicKey>) -> Result<Self, Error> {
        let mut send_noise_map = HashMap::new();
        let mut recv_noise_map = HashMap::new();
        for pubkey in peers_public_keys.iter().cloned() {
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let send_noise = Noise::new(
                builder
                    .local_private_key(&private_key.0)
                    .remote_public_key(&pubkey.0)
                    .build_initiator()?,
            );
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let recv_noise = Noise::new(
                builder
                    .local_private_key(&private_key.0)
                    .remote_public_key(&pubkey.0)
                    .build_responder()?,
            );
            send_noise_map.insert(pubkey.clone(), send_noise);
            recv_noise_map.insert(pubkey.clone(), recv_noise);
        }

        Ok(Self {
            send_noise_map,
            recv_noise_map,
        })
    }

    // Encrypts a message for a given recipient. If `recipient` is None, this
    // will encrypt to the single recipient passed to [`Cipher::new()`]; if more
    // than one was passed, it will panic.
    pub fn encrypt(
        &mut self,
        recipient: Option<&PublicKey>,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let recipient = recipient.cloned().unwrap_or_else(|| {
            if self.send_noise_map.len() == 1 {
                self.send_noise_map.keys().next().unwrap().clone()
            } else {
                panic!("no recipient specified and more than one recipient was passed to `Cipher::new()`");
            }
        });
        let noise = self
            .send_noise_map
            .get_mut(&recipient)
            .ok_or(Error::UnkownRecipient)?;
        let mut encrypted = vec![0; frostd::MAX_MSG_SIZE];
        let len = noise.write_message(&msg, &mut encrypted)?;
        encrypted.truncate(len);
        Ok(encrypted)
    }

    // Decrypts a message.
    // Note that this authenticates the `sender` in the `Msg` struct; if the
    // sender is tampered with, the message would fail to decrypt.
    pub fn decrypt(&mut self, msg: Msg) -> Result<Msg, Error> {
        let noise = self
            .recv_noise_map
            .get_mut(&msg.sender)
            .ok_or(Error::UnkownSender)?;
        let mut decrypted = vec![0; frostd::MAX_MSG_SIZE];
        decrypted.resize(frostd::MAX_MSG_SIZE, 0);
        let len = noise.read_message(&msg.msg, &mut decrypted)?;
        decrypted.truncate(len);
        Ok(Msg {
            sender: msg.sender,
            msg: decrypted,
        })
    }
}
