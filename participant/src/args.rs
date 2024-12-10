use std::{
    env,
    error::Error,
    io::{BufRead, Write},
    rc::Rc,
};

use clap::Parser;
use eyre::eyre;
use frost_core::{
    keys::{KeyPackage, SecretShare},
    Ciphersuite,
};

use crate::input::read_from_file_or_stdin;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'C', long, default_value = "ed25519")]
    pub ciphersuite: String,

    /// CLI mode. If enabled, it will prompt for inputs from stdin
    /// and print values to stdout, ignoring other flags.
    /// If false, socket communication is enabled.
    #[arg(long, default_value_t = false)]
    pub cli: bool,

    /// HTTP mode. If enabled, it will use HTTP communication with a
    /// FROST server.
    #[arg(long, default_value_t = false)]
    pub http: bool,

    /// The username to use in HTTP mode.
    #[arg(short = 'u', long, default_value = "")]
    pub username: String,

    /// The password to use in HTTP mode. If specified, it will be read from the
    /// environment variable with the given name.
    #[arg(short = 'w', long, default_value = "")]
    pub password: String,

    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "". If the file does not exist or if "" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'k', long, default_value = "key-package-1.json")]
    pub key_package: String,

    /// IP to connect to, if using online comms
    #[arg(short, long, default_value = "127.0.0.1")]
    pub ip: String,

    /// Port to connect to, if using online comms
    #[arg(short, long, default_value_t = 2744)]
    pub port: u16,

    /// Optional Session ID
    #[arg(short, long, default_value = "")]
    pub session_id: String,
}

#[derive(Clone)]
pub struct ProcessedArgs<C: Ciphersuite> {
    /// CLI mode. If enabled, it will prompt for inputs from stdin
    /// and print values to stdout, ignoring other flags.
    /// If false, socket communication is enabled.
    pub cli: bool,

    /// HTTP mode. If enabled, it will use HTTP communication with a
    /// FROST server.
    pub http: bool,

    /// The username to use in HTTP mode.
    pub username: String,

    /// The (actual) password to use in HTTP mode.
    pub password: String,

    /// The authentication token to use in HTTP mode; if not specified
    /// it will login with `password`
    pub authentication_token: Option<String>,

    /// Key package to use.
    pub key_package: KeyPackage<C>,

    /// IP to bind to, if using socket comms.
    /// IP to connect to, if using HTTP mode.
    pub ip: String,

    /// Port to bind to, if using socket comms.
    /// Port to connect to, if using HTTP mode.
    pub port: u16,

    /// Optional Session ID
    pub session_id: String,

    /// The participant's communication private key. Specifying this along with
    /// `comm_coordinator_pubkey_getter` enables encryption.
    pub comm_privkey: Option<Vec<u8>>,

    /// The participant's communication public key.
    pub comm_pubkey: Option<Vec<u8>>,

    /// A function that confirms that a public key from the server is trusted by
    /// the user; returns the same public key.
    // It is a `Rc<dyn Fn>` to make it easier to use;
    // using `fn()` would preclude using closures and using generics would
    // require a lot of code change for something simple.
    #[allow(clippy::type_complexity)]
    pub comm_coordinator_pubkey_getter: Option<Rc<dyn Fn(&Vec<u8>) -> Option<Vec<u8>>>>,
}

impl<C: Ciphersuite + 'static> ProcessedArgs<C> {
    /// Create a ProcessedArgs from a Args.
    ///
    /// Validates inputs and reads/parses arguments.
    pub fn new(
        args: &Args,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
    ) -> Result<Self, Box<dyn Error>> {
        let password = if args.http {
            read_password(&args.password)?
        } else {
            String::new()
        };

        let bytes = read_from_file_or_stdin(input, output, "key package", &args.key_package)?;

        let key_package = if let Ok(secret_share) = serde_json::from_str::<SecretShare<C>>(&bytes) {
            KeyPackage::try_from(secret_share)?
        } else {
            // TODO: Improve error
            serde_json::from_str::<KeyPackage<C>>(&bytes)?
        };

        Ok(ProcessedArgs {
            cli: args.cli,
            http: args.http,
            username: args.username.clone(),
            password,
            key_package,
            ip: args.ip.clone(),
            port: args.port,
            authentication_token: None,
            session_id: args.session_id.clone(),
            comm_privkey: None,
            comm_pubkey: None,
            comm_coordinator_pubkey_getter: None,
        })
    }
}

pub fn read_password(password_env_name: &str) -> Result<String, Box<dyn Error>> {
    if password_env_name.is_empty() {
        Ok(
            rpassword::prompt_password("Password: ")
                .map_err(|_| eyre!("Error reading password"))?,
        )
    } else {
        Ok(env::var(password_env_name).map_err(|_| eyre!("The password argument must specify the name of a environment variable containing the password"))?)
    }
}
