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
