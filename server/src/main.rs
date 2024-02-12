use clap::Parser;
use server::args::Args;
use server::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // initialize tracing
    tracing_subscriber::fmt::init();
    run(&args).await
}
