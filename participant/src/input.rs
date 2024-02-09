use std::{
    error::Error,
    fs,
    io::{BufRead, Write},
    path::Path,
};

/// Read the contents of a file or from a stdin.
/// If `object_name` is "-" or a file that does not exist, then it reads from
/// stdin.
/// `object_name` is used for printing prompts and it should describe what
/// is being read.
pub fn read_from_file_or_stdin(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    object_name: &str,
    file_path: &str,
) -> Result<String, Box<dyn Error>> {
    let file_path = {
        if file_path == "-" {
            None
        } else {
            let p = Path::new(&file_path);
            if p.exists() {
                writeln!(output, "Reading {} from {}", object_name, file_path)?;
                Some(p)
            } else {
                writeln!(
                    output,
                    "File not found: {}\nWill read from stdin",
                    file_path
                )?;
                None
            }
        }
    };
    match file_path {
        Some(file_path) => Ok(fs::read_to_string(file_path)?),
        None => {
            writeln!(output, "Paste the {}: ", object_name)?;
            let mut key_package = String::new();
            input.read_line(&mut key_package)?;
            Ok(key_package)
        }
    }

    // TODO: write to file
}
