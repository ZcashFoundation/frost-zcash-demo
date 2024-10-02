use std::error::Error;

use crate::{args::Command, config::Config};

pub(crate) fn list(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Groups { config } = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    for group in config.group.values() {
        eprint!("{}", group.as_human_readable_summary(&config)?);
        eprintln!();
    }

    Ok(())
}
