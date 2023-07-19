use std::io::{BufRead, Write};

use crate::step_1::step_1;
use crate::step_2::step_2;
use crate::step_3::step_3;

pub fn cli(
    reader: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(logger, "\n=== STEP 1: CHOOSE PARTICIPANTS ===\n")?;

    let participants_config = step_1(reader, logger)?;

    writeln!(
        logger,
        "=== STEP 2: CHOOSE MESSAGE AND GENERATE COMMITMENT PACKAGE ===\n"
    )?;

    let signing_package = step_2(reader, logger, participants_config.participants.clone());

    writeln!(logger, "=== STEP 3: BUILD GROUP SIGNATURE ===\n")?;

    step_3(reader, logger, participants_config, signing_package);

    writeln!(logger, "=== END ===")?;

    Ok(())
}
