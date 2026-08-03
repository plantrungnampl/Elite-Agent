use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

pub fn rename_fixture(from: &Path, to: &Path, operation: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match fs::rename(from, to) {
            Ok(()) => return,
            Err(error)
                if cfg!(windows)
                    && matches!(error.raw_os_error(), Some(5 | 32 | 33))
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("{operation}: {error}"),
        }
    }
}
