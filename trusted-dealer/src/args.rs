use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// CLI mode. If enabled, it will prompt for inputs from stdin
    /// and print values to stdout, ignoring other flags.
    /// If false, it will be non-interactive.
    #[arg(long, default_value_t = false)]
    pub cli: bool,

    /// Where to write the public key package to use. Can be a file path or "-".
    /// If "-" is specified, then it will be written to standard output.
    #[arg(short = 'P', long, default_value = "public-key-package.json")]
    pub public_key_package: String,

    /// Template for the key package to be written. If "-" is specified, they will
    /// be all written to standard output. Otherwise, they will be written
    /// to files using the specified format, replacing "{}" with the index
    /// of the participant starting from 1.
    #[arg(short = 'k', long, default_value = "key-package-{}.json")]
    pub key_package: String,

    /// The threshold (minimum number of signers).
    #[arg(short = 't', long, default_value_t = 2)]
    pub threshold: u16,

    /// The total number of participants (maximum number of signers).
    #[arg(short = 'n', long, default_value_t = 3)]
    pub num_signers: u16,

    /// The key to use when splitting into shares, in hex format. If not
    /// specified, a random one will be generated.
    #[arg(long)]
    pub key: Option<String>,
}
