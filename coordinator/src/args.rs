use std::{
    env,
    error::Error,
    fs,
    io::{BufRead, Write},
};

use clap::Parser;
use eyre::eyre;

use frost_core::{keys::PublicKeyPackage, Ciphersuite};
use frost_rerandomized::Randomizer;

use crate::input::read_from_file_or_stdin;

#[derive(Clone, Parser, Debug, Default)]
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

    /// The comma-separated usernames of the signers to use in HTTP mode.
    /// If HTTP mode is enabled and this is empty, then the session ID
    /// will be printed and will have to be shared manually.
    #[arg(short = 'S', long, value_delimiter = ',')]
    pub signers: Vec<String>,

    /// The number of participants. If `signers` is specified, it will use the
    /// length of `signers`. Otherwise, if 0, it will prompt for a value.
    #[arg(short = 'n', long, default_value_t = 0)]
    pub num_signers: u16,

    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "-". If the file does not exist or if "-" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'P', long, default_value = "public-key-package.json")]
    pub public_key_package: String,

    /// The messages to sign. Each instance can be a file with the raw message,
    /// "" or "-". If "" or "-" is specified, then it will be read from standard
    /// input as a hex string. If none are passed, a single one will be read
    /// from standard input as a hex string.
    #[arg(short = 'm', long)]
    pub message: Vec<String>,

    /// The randomizers to use. Each instance can be a file with the raw
    /// randomizer, "" or "-". If "" or "-" is specified, then it will be read
    /// from standard input as a hex string. If none are passed, random ones
    /// will be generated. If one or more are passed, the number should match
    /// the `message` parameter.
    #[arg(short = 'r', long)]
    pub randomizer: Vec<String>,

    /// Where to write the generated raw bytes signature. If "-", the
    /// human-readable hex-string is printed to stdout.
    #[arg(short = 's', long, default_value = "")]
    pub signature: String,

    /// IP to bind to, if using online comms
    #[arg(short, long, default_value = "0.0.0.0")]
    pub ip: String,

    /// Port to bind to, if using online comms
    #[arg(short, long, default_value_t = 2744)]
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ProcessedArgs<C: Ciphersuite> {
    pub ciphersuite: String,

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

    /// The comma-separated usernames of the signers to use in HTTP mode.
    /// If HTTP mode is enabled and this is empty, then the session ID
    /// will be printed and will have to be shared manually.
    pub signers: Vec<String>,

    /// The number of participants.
    pub num_signers: u16,

    /// Public key package to use.
    pub public_key_package: PublicKeyPackage<C>,

    /// The messages to sign.
    pub messages: Vec<Vec<u8>>,

    /// The randomizers to use.
    pub randomizers: Vec<Randomizer<C>>,

    /// Where to write the generated raw bytes signature. If "-", the
    /// human-readable hex-string is printed to stdout.
    pub signature: String,

    /// IP to bind to, if using online comms
    pub ip: String,

    /// Port to bind to, if using online comms
    pub port: u16,
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
            env::var(&args.password).map_err(|_| eyre!("The password argument must specify the name of a environment variable containing the password"))?
        } else {
            String::new()
        };

        let num_signers = if !args.signers.is_empty() {
            args.signers.len() as u16
        } else if args.num_signers == 0 {
            writeln!(output, "The number of participants: ")?;

            let mut participants = String::new();
            input.read_line(&mut participants)?;
            participants.trim().parse::<u16>()?
        } else {
            args.num_signers
        };

        let out = read_from_file_or_stdin(
            input,
            output,
            "public key package",
            &args.public_key_package,
        )?;

        let public_key_package: PublicKeyPackage<C> = serde_json::from_str(&out)?;

        let messages = if args.message.is_empty() {
            writeln!(output, "The message to be signed (hex encoded)")?;
            let mut msg = String::new();
            input.read_line(&mut msg)?;
            vec![hex::decode(msg.trim())?]
        } else {
            args.message
                .iter()
                .map(|filename| {
                    let msg = if filename == "-" || filename.is_empty() {
                        writeln!(output, "The message to be signed (hex encoded)")?;
                        let mut msg = String::new();
                        input.read_line(&mut msg)?;
                        hex::decode(msg.trim())?
                    } else {
                        eprintln!("Reading message from {}...", &filename);
                        fs::read(filename)?
                    };
                    Ok(msg)
                })
                .collect::<Result<_, Box<dyn Error>>>()?
        };

        println!("Processing randomizer {:?}", args.randomizer);
        let randomizers = if args.ciphersuite == "redpallas" {
            if args.randomizer.is_empty() {
                Vec::new()
            } else {
                args.randomizer
                    .iter()
                    .map(|filename| {
                        let randomizer = if filename == "-" || filename.is_empty() {
                            writeln!(output, "Enter the randomizer (hex string):")?;
                            let mut randomizer = String::new();
                            input.read_line(&mut randomizer)?;
                            let bytes = hex::decode(randomizer.trim())?;
                            frost_rerandomized::Randomizer::deserialize(&bytes)?
                        } else {
                            eprintln!("Reading randomizer from {}...", &filename);
                            let bytes = fs::read(filename)?;
                            frost_rerandomized::Randomizer::deserialize(&bytes)?
                        };
                        Ok(randomizer)
                    })
                    .collect::<Result<_, Box<dyn Error>>>()?
            }
        } else {
            Vec::new()
        };

        Ok(ProcessedArgs {
            ciphersuite: args.ciphersuite.clone(),
            cli: args.cli,
            http: args.http,
            username: args.username.clone(),
            password,
            signers: args.signers.clone(),
            num_signers,
            public_key_package,
            messages,
            randomizers,
            signature: args.signature.clone(),
            ip: args.ip.clone(),
            port: args.port,
        })
    }
}
