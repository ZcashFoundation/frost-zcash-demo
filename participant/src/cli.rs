use crate::args::Args;

use crate::comms::cli::CLIComms;
use crate::comms::socket::SocketComms;

use crate::comms::Comms;

use crate::round1::{generate_nonces_and_commitments, print_values, request_inputs};
use crate::round2::{generate_signature, print_values_round_2, round_2_request_inputs};
use rand::thread_rng;
use std::io::{BufRead, Write};

pub async fn cli(
    args: &Args,
    input: &mut impl BufRead,
    logger: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut comms: Box<dyn Comms> = if args.cli {
        Box::new(CLIComms {})
    } else {
        Box::new(SocketComms::new(args))
    };

    // Round 1

    let round_1_config = request_inputs(args, input, logger).await?;
    let key_package = round_1_config.key_package;

    writeln!(logger, "Key Package succesfully created.")?;

    let mut rng = thread_rng();
    let (nonces, commitments) = generate_nonces_and_commitments(&key_package, &mut rng);

    print_values(commitments, logger)?;

    // Round 2 - Sign

    let round_2_config = round_2_request_inputs(
        &mut *comms,
        input,
        logger,
        commitments,
        *key_package.identifier(),
    )
    .await?;
    let signature = generate_signature(round_2_config, &key_package, &nonces)?;

    comms.send_signature_share(signature).await?;

    print_values_round_2(signature, logger)?;

    Ok(())
}
