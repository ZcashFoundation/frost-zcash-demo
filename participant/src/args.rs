use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Public key package to use. Can be a file with a JSON-encoded
    /// package, or "-". If the file does not exist or if "-" is specified,
    /// then it will be read from standard input.
    #[arg(short = 'P', long, default_value = "key-package-1.json")]
    pub key_package: String,

    /// IP to bind to, if using online comms
    #[arg(short, long, default_value = "0.0.0.0")]
    pub ip: String,

    /// Port to bind to, if using online comms
    #[arg(short, long, default_value_t = 2744)]
    pub port: u16,
}
