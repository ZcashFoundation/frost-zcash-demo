//! HTTP implementation of the Comms trait.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    marker::PhantomData,
    time::Duration,
    vec,
};

use tokio::io::{AsyncBufRead as BufRead, AsyncWrite as Write};

use async_trait::async_trait;
use eyre::{eyre, OptionExt};
use frost_core::{
    keys::dkg::{round1, round2},
    Ciphersuite, Identifier,
};

use frostd::{Msg, PublicKey, Uuid};
use participant::comms::http::Noise;
use rand::thread_rng;
use xeddsa::{xed25519, Sign as _};

use super::Comms;
use crate::args::ProcessedArgs;

/// The current state of a session.
///
/// This can be used by a DKG Participant to help maintain state and handle
/// messages from the other Participants.
#[derive(Debug)]
pub enum SessionState<C: Ciphersuite> {
    /// Waiting for participants to send their commitments.
    WaitingForRound1Packages {
        /// Pubkey -> Identifier mapping. This is set during the
        /// get_identifier() call of HTTPComms.
        pubkeys: HashMap<Vec<u8>, Identifier<C>>,
        /// Round 1 Packages sent by participants so far.
        round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
    },
    /// Round 1 Packages have been sent by all other participants. Round 2
    /// Package can be created sent to other participants. Waiting for other
    /// participants to send their Round 2 Packages.
    WaitingForRound2Packages {
        /// Pubkey -> Identifier mapping.
        pubkeys: HashMap<Vec<u8>, Identifier<C>>,
        /// Round 1 Packages sent by participants.
        round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
        /// Round 2 Packages sent by participants so far
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    },
    /// Round 2 Packages have been sent by all other participants; ready to be
    /// fetched by this participant.
    Round2PackagesReady {
        /// Pubkey -> Identifier mapping.
        pubkeys: HashMap<Vec<u8>, Identifier<C>>,
        /// Round 2 Packages sent by participants so far
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    },
}

impl<C: Ciphersuite> Default for SessionState<C> {
    fn default() -> Self {
        Self::WaitingForRound1Packages {
            pubkeys: Default::default(),
            round1_packages: Default::default(),
        }
    }
}

impl<C: Ciphersuite> SessionState<C> {
    /// Handle a Msg received from a participant.
    ///
    /// This should be called for new Msgs until [`are_commitments_ready()`]
    /// returns true, and after the SigningPackage is sent to the participants,
    /// it should be called for new Msgs until [`are_signature_shares_ready()`]
    /// returns true.
    pub fn recv(&mut self, msg: Msg) -> Result<(), Box<dyn Error>> {
        match self {
            SessionState::WaitingForRound1Packages { .. } => {
                let round1_package: round1::Package<C> = serde_json::from_slice(&msg.msg)?;
                self.handle_round1_package(msg.sender, round1_package)?;
            }
            SessionState::WaitingForRound2Packages { .. } => {
                let round2_package: round2::Package<C> = serde_json::from_slice(&msg.msg)?;
                self.handle_round2_package(msg.sender, round2_package)?;
            }
            _ => return Err(eyre!("received message during wrong state").into()),
        }
        Ok(())
    }

    /// Handle commitments sent by a participant.
    fn handle_round1_package(
        &mut self,
        pubkey: Vec<u8>,
        round1_package: round1::Package<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForRound1Packages {
            pubkeys,
            round1_packages,
        } = self
        {
            let identifier = *pubkeys.get(&pubkey).ok_or(eyre!("unknown participant"))?;
            // Add Round 1 Package to map.
            // Currently ignores the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            round1_packages.insert(identifier, round1_package);

            // If complete, advance to next state
            if round1_packages.len() == pubkeys.len() - 1 {
                *self = SessionState::WaitingForRound2Packages {
                    pubkeys: pubkeys.clone(),
                    round1_packages: round1_packages.clone(),
                    round2_packages: Default::default(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns if all participants sent their Round 1 Packages.
    /// When this returns `true`, [`round1_packages()`] can be called.
    pub fn has_round1_packages(&self) -> bool {
        matches!(self, SessionState::WaitingForRound2Packages { .. })
    }

    /// Returns a map linking a participant identifier and the Round 1 Package
    /// they have sent.
    #[allow(clippy::type_complexity)]
    pub fn round1_packages(
        &mut self,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        if let SessionState::WaitingForRound2Packages {
            round1_packages, ..
        } = self
        {
            Ok(round1_packages.clone())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns if all participants sent their Round 2 Packages.
    /// When this returns `true`, [`round2_packages()`] can be called.
    pub fn has_round2_packages(&self) -> bool {
        matches!(self, SessionState::Round2PackagesReady { .. })
    }

    /// Handle signature share sent by a participant.
    fn handle_round2_package(
        &mut self,
        pubkey: Vec<u8>,
        round2_package: round2::Package<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForRound2Packages {
            pubkeys,
            round1_packages,
            round2_packages,
        } = self
        {
            let identifier = pubkeys.get(&pubkey).ok_or(eyre!("unknown participant"))?;
            if !round1_packages.contains_key(identifier) {
                return Err(eyre!("unkown participant").into());
            }

            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            round2_packages.insert(*identifier, round2_package);
            // If complete, advance to next state
            if round2_packages.keys().cloned().collect::<HashSet<_>>()
                == round1_packages.keys().cloned().collect::<HashSet<_>>()
            {
                *self = SessionState::Round2PackagesReady {
                    pubkeys: pubkeys.clone(),
                    round2_packages: round2_packages.clone(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns a map linking a participant identifier and the Round 2 Package
    /// they have sent.
    #[allow(clippy::type_complexity)]
    pub fn round2_packages(
        &mut self,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        if let SessionState::Round2PackagesReady {
            round2_packages, ..
        } = self
        {
            Ok(round2_packages.clone())
        } else {
            panic!("wrong state");
        }
    }
}

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    access_token: Option<String>,
    args: ProcessedArgs<C>,
    state: SessionState<C>,
    pubkeys: HashMap<Vec<u8>, Identifier<C>>,
    // The "send" Noise objects by pubkey of recipients.
    send_noise: Option<HashMap<Vec<u8>, Noise>>,
    // The "receive" Noise objects by pubkey of senders.
    recv_noise: Option<HashMap<Vec<u8>, Noise>>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            host_port: format!("https://{}:{}", args.ip, args.port),
            session_id: None,
            access_token: None,
            args: args.clone(),
            state: SessionState::default(),
            pubkeys: Default::default(),
            send_noise: None,
            recv_noise: None,
            _phantom: Default::default(),
        })
    }

    // Encrypts a message for a given recipient.
    fn encrypt(&mut self, recipient: &Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let noise_map = self
            .send_noise
            .as_mut()
            .expect("send_noise must have been set previously");
        let noise = noise_map
            .get_mut(recipient)
            .ok_or_eyre("unknown recipient")?;
        let mut encrypted = vec![0; 65535];
        let len = noise.write_message(&msg, &mut encrypted)?;
        encrypted.truncate(len);
        Ok(encrypted)
    }

    // Decrypts a message.
    // Note that this authenticates the `sender` in the `Msg` struct; if the
    // sender is tampered with, the message would fail to decrypt.
    fn decrypt(&mut self, msg: Msg) -> Result<Msg, Box<dyn Error>> {
        let noise_map = self
            .recv_noise
            .as_mut()
            .expect("recv_noise must have been set previously");
        let noise = noise_map
            .get_mut(&msg.sender)
            .ok_or_eyre("unknown sender")?;
        let mut decrypted = vec![0; 65535];
        decrypted.resize(65535, 0);
        let len = noise.read_message(&msg.msg, &mut decrypted)?;
        decrypted.truncate(len);
        Ok(Msg {
            sender: msg.sender,
            msg: decrypted,
        })
    }
}

#[async_trait]
impl<C: Ciphersuite + 'static> Comms<C> for HTTPComms<C> {
    async fn get_identifier(
        &mut self,
        _input: &mut (dyn BufRead + Send + Sync + Unpin),
        _output: &mut (dyn Write + Send + Sync + Unpin),
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>> {
        let challenge = self
            .client
            .post(format!("{}/challenge", self.host_port))
            .json(&frostd::ChallengeArgs {})
            .send()
            .await?
            .json::<frostd::ChallengeOutput>()
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
        let signature: [u8; 64] = {
            let mut rng = thread_rng();
            privkey.sign(challenge.as_bytes(), &mut rng)
        };
        let comm_pubkey = self
            .args
            .comm_pubkey
            .clone()
            .ok_or_eyre("comm_pubkey must be specified")?;

        self.access_token = Some(
            self.client
                .post(format!("{}/login", self.host_port))
                .json(&frostd::KeyLoginArgs {
                    challenge,
                    pubkey: comm_pubkey.clone(),
                    signature: signature.to_vec(),
                })
                .send()
                .await?
                .json::<frostd::LoginOutput>()
                .await?
                .access_token
                .to_string(),
        );

        let session_id = if !self.args.participants.is_empty() {
            let r = self
                .client
                .post(format!("{}/create_new_session", self.host_port))
                .bearer_auth(self.access_token.as_ref().expect("was just set"))
                .json(&frostd::CreateNewSessionArgs {
                    pubkeys: self
                        .args
                        .participants
                        .iter()
                        .cloned()
                        .map(PublicKey)
                        .collect(),
                    message_count: 1,
                })
                .send()
                .await?
                .json::<frostd::CreateNewSessionOutput>()
                .await?;
            r.session_id
        } else {
            match self.session_id {
                Some(s) => s,
                None => {
                    // Get session ID from server
                    let r = self
                        .client
                        .post(format!("{}/list_sessions", self.host_port))
                        .bearer_auth(self.access_token.as_ref().expect("was just set"))
                        .send()
                        .await?
                        .json::<frostd::ListSessionsOutput>()
                        .await?;
                    if r.session_ids.len() > 1 {
                        return Err(eyre!("user has more than one FROST session active; use `frost-client sessions` to list them and specify the session ID with `-S`").into());
                    } else if r.session_ids.is_empty() {
                        return Err(eyre!("User has no current sessions active").into());
                    }
                    r.session_ids[0]
                }
            }
        };
        self.session_id = Some(session_id);

        // Get all participants' public keys, and derive their identifiers
        // from them.
        let session_info = self
            .client
            .post(format!("{}/get_session_info", self.host_port))
            .json(&frostd::GetSessionInfoArgs { session_id })
            .bearer_auth(self.access_token.as_ref().expect("was just set"))
            .send()
            .await?
            .json::<frostd::GetSessionInfoOutput>()
            .await?;
        self.pubkeys = session_info
            .pubkeys
            .iter()
            .map(|p| {
                Ok((
                    p.0.clone(),
                    Identifier::<C>::derive(&[session_id.as_bytes(), &p.0[..]].concat())?,
                ))
            })
            .collect::<Result<_, frost_core::Error<C>>>()?;
        // Copy the pubkeys into the state.
        match self.state {
            SessionState::WaitingForRound1Packages {
                ref mut pubkeys, ..
            } => {
                *pubkeys = self.pubkeys.clone();
            }
            _ => unreachable!("wrong state"),
        }

        // Compute this user's identifier by deriving it from the concatenation
        // of the session ID and the communication public key.
        // This ensures the identifier is unique and that participants can
        // derive each other's identifiers.
        let input = [session_id.as_bytes(), &comm_pubkey[..]].concat();
        Ok((Identifier::<C>::derive(&input)?, self.pubkeys.len() as u16))
    }

    async fn get_round1_packages(
        &mut self,
        _input: &mut (dyn BufRead + Send + Sync + Unpin),
        _output: &mut (dyn Write + Send + Sync + Unpin),
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        let (Some(comm_privkey), Some(comm_participant_pubkey_getter)) = (
            &self.args.comm_privkey,
            &self.args.comm_participant_pubkey_getter,
        ) else {
            return Err(
                eyre!("comm_privkey and comm_participant_pubkey_getter must be specified").into(),
            );
        };

        let mut send_noise_map = HashMap::new();
        let mut recv_noise_map = HashMap::new();
        for pubkey in self.pubkeys.keys() {
            let comm_participant_pubkey = comm_participant_pubkey_getter(pubkey).ok_or_eyre("A participant in specified FROST session is not registered in the user's address book")?;
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let send_noise = Noise::new(
                builder
                    .local_private_key(comm_privkey)
                    .remote_public_key(&comm_participant_pubkey)
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
                    .remote_public_key(&comm_participant_pubkey)
                    .build_responder()?,
            );
            send_noise_map.insert(pubkey.clone(), send_noise);
            recv_noise_map.insert(pubkey.clone(), recv_noise);
        }
        self.send_noise = Some(send_noise_map);
        self.recv_noise = Some(recv_noise_map);

        // Send Round 1 Package to all other participants
        for pubkey in self.pubkeys.clone().keys() {
            if Some(pubkey) == self.args.comm_pubkey.as_ref() {
                continue;
            }
            let msg = self.encrypt(pubkey, serde_json::to_vec(&round1_package)?)?;
            self.client
                .post(format!("{}/send", self.host_port))
                .bearer_auth(self.access_token.as_ref().expect("was just set"))
                .json(&frostd::SendArgs {
                    session_id: self.session_id.expect("set before"),
                    recipients: vec![PublicKey(pubkey.clone())],
                    msg,
                })
                .send()
                .await?;
        }

        eprint!("Waiting for other participants to send their Round 1 Packages...");

        loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(
                    self.access_token
                        .as_ref()
                        .expect("must have been set before"),
                )
                .json(&frostd::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .send()
                .await?
                .json::<frostd::ReceiveOutput>()
                .await?;
            for msg in r.msgs {
                let msg = self.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_round1_packages() {
                break;
            }
        }
        eprintln!();

        self.state.round1_packages()
    }

    async fn get_round2_packages(
        &mut self,
        _input: &mut (dyn BufRead + Send + Sync + Unpin),
        _output: &mut (dyn Write + Send + Sync + Unpin),
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        // Send Round 2 Packages to all other participants
        for (pubkey, identifier) in self.pubkeys.clone().into_iter() {
            if Some(&pubkey) == self.args.comm_pubkey.as_ref() {
                continue;
            }
            let msg = self.encrypt(
                &pubkey,
                serde_json::to_vec(
                    &round2_packages
                        .get(&identifier)
                        .ok_or_eyre("must have Round 2 Package for the given identifier")?,
                )?,
            )?;
            self.client
                .post(format!("{}/send", self.host_port))
                .bearer_auth(self.access_token.as_ref().expect("was just set"))
                .json(&frostd::SendArgs {
                    session_id: self.session_id.expect("set before"),
                    recipients: vec![PublicKey(pubkey.clone())],
                    msg,
                })
                .send()
                .await?;
        }

        eprint!("Waiting for other participants to send their Round 2 Packages...");

        loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(
                    self.access_token
                        .as_ref()
                        .expect("must have been set before"),
                )
                .json(&frostd::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .send()
                .await?
                .json::<frostd::ReceiveOutput>()
                .await?;
            for msg in r.msgs {
                let msg = self.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_round2_packages() {
                break;
            }
        }
        eprintln!();

        if !self.args.participants.is_empty() {
            let _r = self
                .client
                .post(format!("{}/close_session", self.host_port))
                .bearer_auth(
                    self.access_token
                        .as_ref()
                        .expect("must have been set before"),
                )
                .json(&frostd::CloseSessionArgs {
                    session_id: self.session_id.unwrap(),
                })
                .send()
                .await?;
        }

        let _r = self
            .client
            .post(format!("{}/logout", self.host_port))
            .bearer_auth(
                self.access_token
                    .as_ref()
                    .expect("must have been set before"),
            )
            .send()
            .await?;

        self.state.round2_packages()
    }

    fn get_pubkey_identifier_map(&self) -> Result<HashMap<Vec<u8>, Identifier<C>>, Box<dyn Error>> {
        match &self.state {
            SessionState::Round2PackagesReady { pubkeys, .. } => Ok(pubkeys.clone()),
            _ => Err(eyre!("wrong state").into()),
        }
    }
}
