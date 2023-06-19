use crate::cli::cli;
use participant::Logger;

pub struct TestLogger(Vec<String>);

impl Logger for TestLogger {
    fn log(&mut self, value: String) {
        self.0.push(value);
    }
}

#[test]
fn check_cli() {
    let mut reader =
        "1\n929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509\n".as_bytes();
    let mut test_logger = TestLogger(Vec::new());
    cli(&mut reader, &mut test_logger);

    assert_eq!(
        test_logger.0[0],
        format!("Your identifier (this should be an integer between 1 and 65535):")
    );
    assert_eq!(test_logger.0[1], format!("Your public key:"))
}
