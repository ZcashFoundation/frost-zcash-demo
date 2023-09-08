use dkg::cli::cli;

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::thread;

use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::Identifier;

// Read a single line from the given reader.
fn read_line(mut reader: impl BufRead) -> Result<String, std::io::Error> {
    let mut s = String::new();
    reader.read_line(&mut s).map(|_| s)
}

// Test if the DKG CLI works.
//
// This simulates 3 simultaneous CLIs by using threads.
//
// Since the `pipe` module used for sending and receiving to each thread
// is synchronous, the test is very strict. For example, you won't be able to
// read from a CLI if it's waiting for input, and you can't write to it if it's
// waiting for some output to be read.
//
// If the test gets stuck somewhere, that's likely the reason: you should be
// writing to a CLI instead of reading, or vice-versa. Use `debug` to find
// where in the function it's getting stuck and check if the test at that point
// is correct.
#[test]
#[allow(clippy::needless_range_loop)]
fn check_dkg() {
    let mut input_writers = Vec::new();
    let mut output_readers = Vec::new();
    let mut join_handles = Vec::new();

    for i in 0..3 {
        // Spawn CLIs, one thread per participant

        let (mut input_reader, input_writer) = pipe::pipe();
        let (output_reader, mut output_writer) = pipe::pipe();
        join_handles.push(thread::spawn(move || {
            cli(&mut input_reader, &mut output_writer).unwrap()
        }));
        input_writers.push(input_writer);
        output_readers.push(output_reader);

        // Input the config into each CLI

        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "The minimum number of signers: (2 or more)\n"
        );
        writeln!(&mut input_writers[i], "2").unwrap();

        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "The maximum number of signers:\n"
        );
        writeln!(&mut input_writers[i], "3").unwrap();

        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "Your identifier (this should be an integer between 1 and 65535):\n"
        );
        writeln!(&mut input_writers[i], "{}", i + 1).unwrap();
    }

    let mut round1_packages = HashMap::new();
    for i in 0..3 {
        // Read the Round 1 Packages printed by each participant;
        // put them in a map
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "=== ROUND 1: SEND PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        assert!(read_line(&mut output_readers[i])
            .unwrap()
            .starts_with("Round 1 Package to send to all other participants"));
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

        let round1_package_json = read_line(&mut output_readers[i]).unwrap();

        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

        round1_packages.insert(i, round1_package_json);
    }

    let mut round2_packages = HashMap::new();
    for i in 0..3 {
        // Input the Round 1 Packages from other participants, for each
        // participant i
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "=== ROUND 1: RECEIVE PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "Input Round 1 Packages from the other 2 participants.\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        for j in 0..3 {
            // Input Round 1 Package from participant j
            if i == j {
                continue;
            };
            assert_eq!(
                read_line(&mut output_readers[i]).unwrap(),
                "The sender's identifier (hex string):\n"
            );

            // Write j's identifier
            let jid: Identifier = ((j + 1) as u16).try_into().unwrap();
            writeln!(&mut input_writers[i], "{}", hex::encode(jid.serialize())).unwrap();

            assert_eq!(
                read_line(&mut output_readers[i]).unwrap(),
                "Their JSON-encoded Round 1 Package:\n"
            );

            // Write j's package
            write!(&mut input_writers[i], "{}", round1_packages[&j]).unwrap();

            assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        }

        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "=== ROUND 2: SEND PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

        let mut packages = HashMap::new();
        for j in 0..3 {
            // Read Round 2 packages to send to other participants, for
            // each participant
            if i == j {
                continue;
            };
            // Read line indicating who should receive that package;
            // extract hex identifier
            let s = read_line(&mut output_readers[i]).unwrap();
            assert!(s.starts_with("Round 2 Package to send to participant"));
            let participant_hex = s.split('\"').collect::<Vec<_>>()[1].to_string();

            assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

            // Read Round 2 package
            let round2_package_json = read_line(&mut output_readers[i]).unwrap();

            assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

            packages.insert(participant_hex, round2_package_json);
        }
        round2_packages.insert(i, packages);
    }

    let mut public_key_packages = HashMap::new();
    for i in 0..3 {
        // Input Round 2 packages from other participants, for each participant
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "=== ROUND 2: RECEIVE PACKAGES ===\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "Input Round 2 Packages from the other 2 participants.\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        for j in 0..3 {
            // Input Round 2 Package from participant j
            if i == j {
                continue;
            };
            assert_eq!(
                read_line(&mut output_readers[i]).unwrap(),
                "The sender's identifier (hex string):\n"
            );

            // Write j's identifier
            let jid: Identifier = ((j + 1) as u16).try_into().unwrap();
            writeln!(&mut input_writers[i], "{}", hex::encode(jid.serialize())).unwrap();

            assert_eq!(
                read_line(&mut output_readers[i]).unwrap(),
                "Their JSON-encoded Round 2 Package:\n"
            );

            // Write j's package sent to i
            let iid: Identifier = ((i + 1) as u16).try_into().unwrap();
            let iids = hex::encode(iid.serialize());
            let s = round2_packages.get(&j).expect("j").get(&iids).expect("i");
            write!(&mut input_writers[i], "{}", s).unwrap();

            assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        }

        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "=== DKG FINISHED ===\n"
        );
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "Participant key package:\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

        // Read key package
        let key_package_json = read_line(&mut output_readers[i]).unwrap();
        let _key_package: KeyPackage = serde_json::from_str(&key_package_json).unwrap();

        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");
        assert_eq!(
            read_line(&mut output_readers[i]).unwrap(),
            "Participant public key package:\n"
        );
        assert_eq!(read_line(&mut output_readers[i]).unwrap(), "\n");

        // Read public key package
        let public_key_package_json = read_line(&mut output_readers[i]).unwrap();
        let public_key_package: PublicKeyPackage =
            serde_json::from_str(&public_key_package_json).unwrap();
        public_key_packages.insert(i, public_key_package);
    }

    // Check that all public key packages are equal
    assert!(public_key_packages
        .values()
        .all(|p| *p == public_key_packages[&0]));

    // Wait for threads, which should terminate at this point
    for jh in join_handles {
        jh.join().unwrap();
    }
}
