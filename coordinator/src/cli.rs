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
    cli_for_processed_args(pargs, reader, logger).await
}

pub async fn cli_for_processed_args<C: RandomizedCiphersuite + 'static>(
    pargs: ProcessedArgs<C>,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut comms: Box<dyn Comms<C>> = if pargs.cli {
        Box::new(CLIComms::new())
    } else if pargs.http {
        Box::new(HTTPComms::new(&pargs)?)
    } else {
        Box::new(SocketComms::new(&pargs))
    };

    let r = step_1(&pargs, &mut *comms, reader, logger).await;
    let Ok(participants_config) = r else {
        let _ = comms.cleanup_on_error().await;
        return Err(r.unwrap_err());
    };

    let r = step_2(&pargs, logger, participants_config.commitments.clone());
    let Ok(signing_package) = r else {
        let _ = comms.cleanup_on_error().await;
        return Err(r.unwrap_err());
    };

    let r = step_3(
        &pargs,
        &mut *comms,
        reader,
        logger,
        participants_config,
        &signing_package,
    )
    .await;

    if let Err(e) = r {
        let _ = comms.cleanup_on_error().await;
        return Err(e);
    }

    Ok(())
}
