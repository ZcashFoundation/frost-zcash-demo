//! HTTP implementation of the Comms trait.

use std::{
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{
    self as frost, round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier,
};
use rand::thread_rng;
use snow::{HandshakeState, TransportState};
use xeddsa::{xed25519, Sign as _};

use super::Comms;
use crate::args::ProcessedArgs;

/// A Noise state.
///
/// This abstracts away some awkwardness in the `snow` crate API, which
/// requires explicitly marking the handshake as finished and switching
/// to a new state object after the first message is sent.
pub struct Noise {
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

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    access_token: String,
    should_logout: bool,
    args: ProcessedArgs<C>,
    send_noise: Option<Noise>,
    recv_noise: Option<Noise>,
    _phantom: PhantomData<C>,
}

use server::{SendCommitmentsArgs, SendSignatureSharesArgs, SendSigningPackageArgs, Uuid};

// TODO: Improve error handling for invalid session id
impl<C> HTTPComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: Uuid::parse_str(&args.session_id).ok(),
            access_token: args.authentication_token.clone().unwrap_or_default(),
            should_logout: args.authentication_token.is_none(),
            args: args.clone(),
            send_noise: None,
            recv_noise: None,
            _phantom: Default::default(),
        })
    }

    // Encrypts a message for the coordinator if encryption is enabled.
    fn encrypt_if_needed(&mut self, msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(noise) = &mut self.send_noise {
            let mut encrypted = vec![0; 65535];
            let len = noise.write_message(&msg, &mut encrypted)?;
            encrypted.truncate(len);
            Ok(encrypted)
        } else {
            Ok(msg)
        }
    }

    // Decrypts a message from the coordinator if encryption is enabled.
    fn decrypt_if_needed(&mut self, msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(noise) = &mut self.recv_noise {
            let mut decrypted = vec![0; 65535];
            decrypted.resize(65535, 0);
            let len = noise.read_message(&msg, &mut decrypted)?;
            decrypted.truncate(len);
            Ok(decrypted)
        } else {
            Ok(msg)
        }
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for HTTPComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_signing_package(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        commitments: SigningCommitments<C>,
        identifier: Identifier<C>,
        rerandomized: bool,
    ) -> Result<
        (
            frost::SigningPackage<C>,
            Option<frost_rerandomized::Randomizer<C>>,
        ),
        Box<dyn Error>,
    > {
        let mut rng = thread_rng();
        let challenge = self
            .client
            .post(format!("{}/challenge", self.host_port))
            .json(&server::ChallengeArgs {})
            .send()
            .await?
            .json::<server::ChallengeOutput>()
            .await?
            .challenge;

        let privkey = xed25519::PrivateKey::from(
            &TryInto::<[u8; 32]>::try_into(
                self.args
                    .comm_privkey
                    .clone()
                    .ok_or_eyre("comm_privkey must be specified")?,
            )
            .map_err(|_| eyre!("invalid comm_privkey"))?,
        );
        let signature: [u8; 64] = privkey.sign(challenge.as_bytes(), &mut rng);

        self.access_token = self
            .client
            .post(format!("{}/key_login", self.host_port))
            .json(&server::KeyLoginArgs {
                uuid: challenge,
                pubkey: self
                    .args
                    .comm_pubkey
                    .clone()
                    .ok_or_eyre("comm_pubkey must be specified")?,
                signature: signature.to_vec(),
            })
            .send()
            .await?
            .json::<server::LoginOutput>()
            .await?
            .access_token
            .to_string();

        let session_id = match self.session_id {
            Some(s) => s,
            None => {
                // Get session ID from server
                let r = self
                    .client
                    .post(format!("{}/list_sessions", self.host_port))
                    .bearer_auth(&self.access_token)
                    .send()
                    .await?
                    .json::<server::ListSessionsOutput>()
                    .await?;
                if r.session_ids.len() > 1 {
                    return Err(eyre!("user has more than one FROST session active, which is still not supported by this tool").into());
                } else if r.session_ids.is_empty() {
                    return Err(eyre!("User has no current sessions active. The Coordinator should either specify your username, or manually share the session ID which you can specify with --session_id").into());
                }
                r.session_ids[0]
            }
        };
        self.session_id = Some(session_id);

        // If encryption is enabled, create the Noise objects
        (self.send_noise, self.recv_noise) = if let (
            Some(comm_privkey),
            Some(comm_coordinator_pubkey_getter),
        ) = (
            &self.args.comm_privkey,
            &self.args.comm_coordinator_pubkey_getter,
        ) {
            // We need to know what is the username of the coordinator in order
            // to encrypt message to them.
            let session_info = self
                .client
                .post(format!("{}/get_session_info", self.host_port))
                .json(&server::GetSessionInfoArgs { session_id })
                .bearer_auth(&self.access_token)
                .send()
                .await?
                .json::<server::GetSessionInfoOutput>()
                .await?;

            let comm_coordinator_pubkey = comm_coordinator_pubkey_getter(&session_info.coordinator_pubkey).ok_or_eyre("The coordinator for the specified FROST session is not registered in the user's address book")?;
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let send_noise = Noise::new(
                builder
                    .local_private_key(comm_privkey)
                    .remote_public_key(&comm_coordinator_pubkey)
                    .build_initiator()?,
            );
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let recv_noise = Noise::new(
                builder
                    .local_private_key(comm_privkey)
                    .remote_public_key(&comm_coordinator_pubkey)
                    .build_responder()?,
            );
            (Some(send_noise), Some(recv_noise))
        } else {
            (None, None)
        };

        // Send Commitments to Server
        let send_commitments_args = SendCommitmentsArgs {
            identifier,
            commitments: vec![commitments],
        };
        let msg = self.encrypt_if_needed(serde_json::to_vec(&send_commitments_args)?)?;
        self.client
            .post(format!("{}/send", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendArgs {
                session_id,
                // Empty recipients: Coordinator
                recipients: vec![],
                msg,
            })
            .send()
            .await?;

        eprint!("Waiting for coordinator to send signing package...");

        // Receive SigningPackage from Coordinator

        let r: SendSigningPackageArgs<C> = loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::ReceiveArgs {
                    session_id,
                    as_coordinator: false,
                })
                .send()
                .await?
                .json::<server::ReceiveOutput>()
                .await?;
            if r.msgs.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                eprintln!("\nSigning package received");
                let msg = self.decrypt_if_needed(r.msgs[0].msg.clone())?;
                eprintln!("\n{}", String::from_utf8_lossy(&msg.clone()));
                break serde_json::from_slice(&msg)?;
            }
        };

        if rerandomized {
            let signing_package = r
                .signing_package
                .first()
                .ok_or(eyre!("missing signing package"))?;
            let randomizer = r.randomizer.first().ok_or(eyre!("missing randomizer"))?;
            Ok((signing_package.clone(), Some(*randomizer)))
        } else {
            let signing_package = r
                .signing_package
                .first()
                .ok_or(eyre!("missing signing package"))?;
            Ok((signing_package.clone(), None))
        }
    }

    async fn send_signature_share(
        &mut self,
        identifier: Identifier<C>,
        signature_share: SignatureShare<C>,
    ) -> Result<(), Box<dyn Error>> {
        // Send signature share to Coordinator

        eprintln!("Sending signature share to coordinator...");

        let send_signature_shares_args = SendSignatureSharesArgs {
            identifier,
            signature_share: vec![signature_share],
        };

        let msg = self.encrypt_if_needed(serde_json::to_vec(&send_signature_shares_args)?)?;

        let _r = self
            .client
            .post(format!("{}/send", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendArgs {
                session_id: self.session_id.unwrap(),
                // Empty recipients: Coordinator
                recipients: vec![],
                msg,
            })
            .send()
            .await?;

        if self.should_logout {
            let _r = self
                .client
                .post(format!("{}/logout", self.host_port))
                .bearer_auth(&self.access_token)
                .send()
                .await?;
        }

        Ok(())
    }
}
