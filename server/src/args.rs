use clap::Parser;

#[derive(Parser, Debug, Default)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// IP to bind to
    #[arg(short, long, default_value = "0.0.0.0")]
    pub ip: String,

    /// Port to bind to
    #[arg(short, long, default_value_t = 2744)]
    pub port: u16,
}
