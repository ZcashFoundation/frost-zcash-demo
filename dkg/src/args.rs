use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short = 'C', long, default_value = "ed25519")]
    pub ciphersuite: String,
}
