use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The number of participants. If 0, will prompt for a value.
    #[arg(short = 'n', long, default_value_t = 0)]
    pub num_signers: u16,

    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "-". If the file does not exist or if "-" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'P', long, default_value = "public-key-package.json")]
    pub public_key_package: String,

    /// Where to write the generated raw bytes signature. If "-", the
    /// human-readable hex-string is printed to stdout.
    #[arg(short = 's', long, default_value = "-")]
    pub signature: String,

    /// IP to bind to, if using online comms
    #[arg(short, long, default_value = "0.0.0.0")]
    pub ip: String,

    /// Port to bind to, if using online comms
    #[arg(short, long, default_value_t = 2744)]
    pub port: u16,
}
