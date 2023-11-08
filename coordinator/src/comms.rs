#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
use message_io::{
    network::{Endpoint, NetEvent, NetworkController, Transport},
    node::{self, NodeHandler, NodeListener},
};
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use eyre::eyre;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, Write},
};

use crate::args::Args;

pub enum Message {
    IdentifiedCommitments {
        identifier: Identifier,
        commitments: SigningCommitments,
    },
    SignatureShare(SignatureShare),
}

pub(crate) trait Comms {
    async fn get_signing_commitments(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        pub_key_package: &PublicKeyPackage,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>>;

    async fn get_signature_shares(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        signing_package: &SigningPackage,
        #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>>;
}

pub struct CLIComms {}

impl Comms for CLIComms {
    async fn get_signing_commitments(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        pub_key_package: &PublicKeyPackage,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>> {
        let mut participants_list = Vec::new();
        let mut commitments_list: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();

        for i in 1..=num_of_participants {
            writeln!(output, "Identifier for participant {:?} (hex encoded): ", i)?;
            let id_value = read_identifier(input)?;
            validate(id_value, pub_key_package, &participants_list)?;
            participants_list.push(id_value);

            writeln!(
                output,
                "Please enter JSON encoded commitments for participant {}:",
                hex::encode(id_value.serialize())
            )?;
            let mut commitments_input = String::new();
            input.read_line(&mut commitments_input)?;
            let commitments = serde_json::from_str(&commitments_input)?;
            commitments_list.insert(id_value, commitments);
        }

        Ok(commitments_list)
    }

    async fn get_signature_shares(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        _signing_package: &SigningPackage,
        #[cfg(feature = "redpallas")] _randomizer: frost::round2::Randomizer,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>> {
        let mut signatures_list: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        for p in commitments.keys() {
            writeln!(
                output,
                "Please enter JSON encoded signature shares for participant {}:",
                hex::encode(p.serialize())
            )
            .unwrap();

            let mut signature_input = String::new();
            input.read_line(&mut signature_input)?;
            let signatures = serde_json::from_str(&signature_input)?;
            signatures_list.insert(*p, signatures);
        }
        Ok(signatures_list)
    }
}

pub fn read_identifier(input: &mut dyn BufRead) -> Result<Identifier, Box<dyn Error>> {
    let mut identifier_input = String::new();
    input.read_line(&mut identifier_input)?;
    let bytes = hex::decode(identifier_input.trim())?;
    let serialization = bytes.try_into().map_err(|_| eyre!("Invalid Identifier"))?;
    let identifier = Identifier::deserialize(&serialization)?;
    Ok(identifier)
}

pub fn validate(
    id: Identifier,
    key_package: &PublicKeyPackage,
    id_list: &[Identifier],
) -> Result<(), frost::Error> {
    if !key_package.signer_pubkeys().contains_key(&id) {
        return Err(frost::Error::MalformedIdentifier);
    }; // TODO: Error is actually that the identifier does not exist
    if id_list.contains(&id) {
        return Err(frost::Error::DuplicatedIdentifier);
    };
    Ok(())
}

pub struct SocketComms {
    input_rx: Receiver<(Endpoint, Vec<u8>)>,
    endpoints: BTreeMap<Identifier, Endpoint>,
    handler: NodeHandler<()>,
}

impl SocketComms {
    pub fn new(args: &Args) -> Self {
        let (handler, listener) = node::split::<()>();
        let addr = format!("{}:{}", args.ip, args.port);
        let (tx, rx) = mpsc::channel(100);

        handler
            .network()
            .listen(Transport::FramedTcp, addr)
            .unwrap();

        let socket_comm = Self {
            input_rx: rx,
            endpoints: BTreeMap::new(),
            handler,
        };

        // TODO: save handle
        let _ = tokio::spawn(async move { Self::run(listener, tx) });

        socket_comm
    }

    fn run(listener: NodeListener<()>, input_tx: Sender<(Endpoint, Vec<u8>)>) {
        // Read incoming network events.
        listener.for_each(|event| match event.network() {
            NetEvent::Connected(_, _) => unreachable!(), // Used for explicit connections.
            NetEvent::Accepted(_endpoint, _listener) => println!("Client connected"), // Tcp or Ws
            NetEvent::Message(endpoint, data) => {
                println!("Received: {}", String::from_utf8_lossy(data));
                // TODO: handle error
                let _ = input_tx.try_send((endpoint, data.to_vec()));
            }
            NetEvent::Disconnected(_endpoint) => println!("Client disconnected"), //Tcp or Ws
        });
    }
}

impl Comms for SocketComms {
    async fn get_signing_commitments(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        _pub_key_package: &PublicKeyPackage,
        num_of_participants: u16,
    ) -> Result<BTreeMap<Identifier, SigningCommitments>, Box<dyn Error>> {
        let signing_commitments = BTreeMap::new();
        for _ in 0..num_of_participants {
            let (endpoint, _data) = self
                .input_rx
                .recv()
                .await
                .ok_or(eyre!("Did not receive all commitments"))?;
            // TODO: parse data and insert into map
            self.endpoints
                .insert(Identifier::try_from(1u16).unwrap(), endpoint);
        }
        Ok(signing_commitments)
    }

    async fn get_signature_shares(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        commitments: &BTreeMap<Identifier, SigningCommitments>,
        _signing_package: &SigningPackage,
        #[cfg(feature = "redpallas")] _randomizer: frost::round2::Randomizer,
    ) -> Result<BTreeMap<Identifier, SignatureShare>, Box<dyn Error>> {
        for identifier in commitments.keys() {
            let endpoint = self
                .endpoints
                .get(identifier)
                .ok_or(eyre!("unknown identifier"))?;
            self.handler.network().send(*endpoint, &[]);
        }
        Ok(BTreeMap::new())
    }
}
