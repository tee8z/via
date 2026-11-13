use std::io::{self, Write};

// Writes capability output to standard output. A failure, such as a pipe
// that the reader has closed, is an error here and not a panic as it is with
// `print!`. A broker request must reach its audit record even when the
// caller has already disconnected.
pub(crate) fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    if cfg!(test) {
        // The test harness only captures output written through `print!`.
        print!("{}", String::from_utf8_lossy(bytes));
        return Ok(());
    }

    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()
}
