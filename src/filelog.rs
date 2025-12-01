use std::fs::{OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn write_line(path: &str, line: &str) {
    let p = Path::new(path);
    let f = OpenOptions::new().create(true).append(true).open(p).ok();
    if let Some(mut file) = f {
        let _ = writeln!(file, "{}", line);
    }
}
