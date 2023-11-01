use std::io::{BufRead, Write};

use crate::args::Args;
use crate::comms::CLIComms;
use crate::step_1::step_1;
use crate::step_2::step_2;
use crate::step_3::step_3;

#[cfg(feature = "redpallas")]
use crate::step_3::request_randomizer;

pub async fn cli(
    args: &Args,
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(logger, "\n=== STEP 1: CHOOSE PARTICIPANTS ===\n")?;

    let comms = CLIComms {
        input: reader,
        output: logger,
    };

    let participants_config = step_1(args, comms, reader, logger).await?;

    writeln!(
        logger,
        "=== STEP 2: CHOOSE MESSAGE AND GENERATE COMMITMENT PACKAGE ===\n"
    )?;

    let signing_package = step_2(reader, logger, participants_config.commitments.clone())?;

    #[cfg(feature = "redpallas")]
    let randomizer = request_randomizer(reader, logger)?;

    writeln!(logger, "=== STEP 3: BUILD GROUP SIGNATURE ===\n")?;

    step_3(
        reader,
        logger,
        participants_config,
        signing_package,
        #[cfg(feature = "redpallas")]
        randomizer,
    );

    writeln!(logger, "=== END ===")?;

    Ok(())
}
