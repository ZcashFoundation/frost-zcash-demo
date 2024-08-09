use clap::Parser;

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

    /// The comma-separated usernames of the signers to use in HTTP mode.
    /// If HTTP mode is enabled and this is empty, then the session ID
    /// will be printed and will have to be shared manually.
    #[arg(short = 'S', long, value_delimiter = ',')]
    pub signers: Vec<String>,

    /// The number of participants. If 0, will prompt for a value.
    #[arg(short = 'n', long, default_value_t = 0)]
    pub num_signers: u16,

    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "". If the file does not exist or if "" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'P', long, default_value = "public-key-package.json")]
    pub public_key_package: String,

    /// The message to sign. Can be a file with the raw message, or "". If ""
    /// is specified, then it will be read from standard input as a hex string.
    #[arg(short = 'm', long, default_value = "")]
    pub message: String,

    /// The randomizer to use. Can be a file with the raw randomizer, empty, or
    /// "-". If empty, a random one will be generated. If "-" is specified, then
    /// it will be read from standard input as a hex string.
    #[arg(short = 'r', long, default_value = "")]
    pub randomizer: String,

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
