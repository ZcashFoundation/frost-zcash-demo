mod cli;
#[cfg(test)]
mod tests;

use cli::cli;
use participant::Logger;

use std::io;

fn main() -> io::Result<()> {
    let mut reader = Box::new(io::stdin().lock());
    let mut logger = ConsoleLogger::default();
    cli(&mut reader, &mut logger);

    Ok(())
}

#[derive(Default)]
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn log(&mut self, value: String) {
        println!("{}", value);
    }
}
