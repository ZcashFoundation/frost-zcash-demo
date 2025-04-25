/*!
Write files atomically.

This is based on
https://github.com/Blobfolio/write_atomic/blob/7d9965784cca5b3d54adf8a312323f096223f13d/src/lib.rs
but uses the tempfile `persist()` function, which by default creates files with
reduced permissions.
*/

use std::{
    io::{Error, ErrorKind, Result, Write},
    path::{Path, PathBuf},
};

/// # Atomic File Write!
///
/// This will write bytes atomically to the specified path, or creating it anew
/// readable and writable by the owner only [1].
///
/// ## Examples
///
/// ```no_run
/// use frost_client::write_atomic;
/// // It's just one line:
/// write_atomic::write_file("/path/to/my/file.txt", b"Some data!")
///     .unwrap();
/// ```
///
/// ## Errors
///
/// This will bubble up any filesystem-related errors encountered along the way.
///
/// [1]: https://docs.rs/tempfile/latest/tempfile/struct.Builder.html#security
pub fn write_file<P>(src: P, data: &[u8]) -> Result<()>
where
    P: AsRef<Path>,
{
    let (dst, parent) = check_path(src)?;

    let mut file = tempfile::Builder::new().tempfile_in(parent)?;
    file.write_all(data)?;
    file.flush()?;

    file.persist(dst)?;

    Ok(())
}

/// # Handle Path.
///
/// This checks the path and returns it and its parent, assuming it is valid,
/// or an error if not.
fn check_path<P>(src: P) -> Result<(PathBuf, PathBuf)>
where
    P: AsRef<Path>,
{
    let src = src.as_ref();

    // The path cannot be a directory.
    if src.is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Path cannot be a directory.",
        ));
    }

    // We don't need to fully canonicalize the path, but if there's no stub, it
    // is assumed to be in the "current directory".
    let src: PathBuf = if src.is_absolute() {
        src.to_path_buf()
    } else {
        let mut absolute = std::env::current_dir()?;
        absolute.push(src);
        absolute
    };

    // Make sure it has a parent.
    let parent: PathBuf = src
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "Path must have a parent directory."))?;

    // Create the directory chain if necessary.
    std::fs::create_dir_all(&parent)?;

    // We're good to go!
    Ok((src, parent))
}
