use std::io::{BufRead, Write};

use frost_rerandomized::RandomizedCiphersuite;

use crate::args::Args;
use crate::args::ProcessedArgs;
use crate::comms::cli::CLIComms;
use crate::comms::http::HTTPComms;
use crate::comms::socket::SocketComms;
use crate::comms::Comms;
use crate::step_1::step_1;
use crate::step_2::step_2;
use crate::step_3::step_3;

pub async fn cli<C: RandomizedCiphersuite + 'static>(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let pargs = ProcessedArgs::<C>::new(args, reader, logger)?;

    writeln!(logger, "\n=== STEP 1: CHOOSE PARTICIPANTS ===\n")?;

    let mut comms: Box<dyn Comms<C>> = if args.cli {
        Box::new(CLIComms::new())
    } else if args.http {
        Box::new(HTTPComms::new(&pargs)?)
    } else {
        Box::new(SocketComms::new(args))
    };

    let participants_config = step_1(&pargs, &mut *comms, reader, logger).await?;

    writeln!(
        logger,
        "=== STEP 2: CHOOSE MESSAGE AND GENERATE COMMITMENT PACKAGE ===\n"
    )?;

    let signing_package = step_2(&pargs, logger, participants_config.commitments.clone())?;

    writeln!(logger, "=== STEP 3: BUILD GROUP SIGNATURE ===\n")?;

    step_3(
        &pargs,
        &mut *comms,
        reader,
        logger,
        participants_config,
        &signing_package,
    )
    .await?;

    writeln!(logger, "=== END ===")?;

    Ok(())
}
