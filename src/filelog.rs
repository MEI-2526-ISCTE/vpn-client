use std::fs::{OpenOptions};
use std::io::Write;
use std::path::Path;

/**
 * @brief Append a single line to a log file, creating the file if missing.
 * @param path Path to the log file.
 * @param line Text line to append.
 */
pub fn write_line(path: &str, line: &str) {
    let p = Path::new(path);
    let f = OpenOptions::new().create(true).append(true).open(p).ok();
    if let Some(mut file) = f {
        let _ = writeln!(file, "{}", line);
    }
}
