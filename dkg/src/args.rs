use std::rc::Rc;

use clap::Parser;
use frost_core::{Ciphersuite, Identifier};
use frostd::PublicKey;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'C', long, default_value = "ed25519")]
    pub ciphersuite: String,
}

#[derive(Clone)]
pub struct ProcessedArgs<C: Ciphersuite> {
    /// CLI mode. If enabled, it will prompt for inputs from stdin
    /// and print values to stdout, ignoring other flags.
    pub cli: bool,

    /// HTTP mode. If enabled, it will use HTTP communication with a
    /// FROST server.
    pub http: bool,

    /// IP to connect to, if using HTTP mode.
    pub ip: String,

    /// Port to connect to, if using HTTP mode.
    pub port: u16,

    /// The participant's communication private key for HTTP mode.
    pub comm_privkey: Option<Vec<u8>>,

    /// The participant's communication public key for HTTP mode.
    pub comm_pubkey: Option<PublicKey>,

    /// A function that confirms that a public key from the server is trusted by
    /// the user; returns the same public key. For HTTP mode.
    // It is a `Rc<dyn Fn>` to make it easier to use;
    // using `fn()` would preclude using closures and using generics would
    // require a lot of code change for something simple.
    #[allow(clippy::type_complexity)]
    pub comm_participant_pubkey_getter: Option<Rc<dyn Fn(&PublicKey) -> Option<PublicKey>>>,

    /// The threshold to use for the shares
    pub min_signers: u16,

    /// The total number of signers. Only needed for CLI mode.
    pub max_signers: Option<u16>,

    /// The list of pubkeys for the other participants. This is only required
    /// for the first participant who creates the DKG session.
    pub participants: Vec<PublicKey>,

    /// Identifier to use for the participant. Only needed for CLI mode.
    pub identifier: Option<Identifier<C>>,
}

impl<C> ProcessedArgs<C>
where
    C: Ciphersuite,
{
    pub(crate) fn new(config: &crate::inputs::Config<C>) -> Self {
        Self {
            cli: true,
            http: false,
            ip: String::new(),
            port: 0,
            comm_privkey: None,
            comm_pubkey: None,
            comm_participant_pubkey_getter: None,
            min_signers: config.min_signers,
            max_signers: Some(config.max_signers),
            participants: Vec::new(),
            identifier: Some(config.identifier),
        }
    }
}
