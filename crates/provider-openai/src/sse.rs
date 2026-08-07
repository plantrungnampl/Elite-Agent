use std::io::{self, BufRead};

use local_agent_terminal_agent_protocol::ProtocolError;
use serde_json::Value;

pub const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

pub(crate) struct SseReader<R> {
    reader: R,
    max_event_bytes: usize,
}

impl<R: BufRead> SseReader<R> {
    pub(crate) fn new(reader: R, max_event_bytes: usize) -> Self {
        Self {
            reader,
            max_event_bytes,
        }
    }

    pub(crate) fn next_event(&mut self) -> Result<Option<Value>, ProtocolError> {
        let mut data = Vec::new();
        loop {
            let Some(line) = self.next_line()? else {
                return if data.is_empty() {
                    Ok(None)
                } else {
                    parse_event(&data).map(Some)
                };
            };
            let line = strip_carriage_return(&line);
            if line.is_empty() {
                if !data.is_empty() {
                    return parse_event(&data).map(Some);
                }
                continue;
            }
            if line.starts_with(b":") {
                continue;
            }
            let (field, value) = split_field(line);
            if field == b"data" {
                if !data.is_empty() {
                    append_bounded(&mut data, b"\n", self.max_event_bytes)?;
                }
                append_bounded(&mut data, value, self.max_event_bytes)?;
            }
        }
    }

    fn next_line(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        let mut line = Vec::new();
        loop {
            let available = self.reader.fill_buf().map_err(io_error)?;
            if available.is_empty() {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(line))
                };
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let length = newline.map_or(available.len(), |position| position + 1);
            append_bounded(&mut line, &available[..length], self.max_event_bytes)?;
            self.reader.consume(length);
            if newline.is_some() {
                line.pop();
                return Ok(Some(line));
            }
        }
    }
}

fn split_field(line: &[u8]) -> (&[u8], &[u8]) {
    let Some(separator) = line.iter().position(|byte| *byte == b':') else {
        return (line, b"");
    };
    let value = &line[separator + 1..];
    let value = value.strip_prefix(b" ").unwrap_or(value);
    (&line[..separator], value)
}

fn strip_carriage_return(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn append_bounded(
    destination: &mut Vec<u8>,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ProtocolError> {
    let Some(length) = destination.len().checked_add(bytes.len()) else {
        return Err(ProtocolError::FrameTooLarge {
            max_frame_bytes: maximum,
        });
    };
    if length > maximum {
        return Err(ProtocolError::FrameTooLarge {
            max_frame_bytes: maximum,
        });
    }
    destination.extend_from_slice(bytes);
    Ok(())
}

fn parse_event(bytes: &[u8]) -> Result<Value, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidJson)
}

fn io_error(error: io::Error) -> ProtocolError {
    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<reqwest::Error>())
        .is_some_and(reqwest::Error::is_timeout)
    {
        return ProtocolError::Timeout;
    }
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) || error.to_string().to_ascii_lowercase().contains("timed out")
    {
        ProtocolError::Timeout
    } else {
        ProtocolError::ProviderUnavailable
    }
}
