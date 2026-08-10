use local_agent_terminal_application::{PortError, Retryability, SafeErrorClassification};
use local_agent_terminal_domain::{LineRange, Sha256Digest, SourceIdentity};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct ContextTextSource {
    identity: SourceIdentity,
    language: Option<String>,
    symbol: Option<String>,
    bytes: Vec<u8>,
}

impl ContextTextSource {
    pub fn new(
        identity: SourceIdentity,
        language: Option<&str>,
        symbol: Option<&str>,
        bytes: Vec<u8>,
    ) -> Result<Self, PortError> {
        if bytes.is_empty()
            || bytes.contains(&0)
            || std::str::from_utf8(&bytes).is_err()
            || digest(&bytes) != *identity.content_hash()
            || language.is_some_and(|value| !valid_label(value))
            || symbol.is_some_and(|value| !valid_label(value))
        {
            return Err(invalid());
        }
        Ok(Self {
            identity,
            language: language.map(str::to_owned),
            symbol: symbol.map(str::to_owned),
            bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextTextChunk {
    source: SourceIdentity,
    range: LineRange,
    language: Option<String>,
    symbol: Option<String>,
    bytes: Vec<u8>,
    content_digest: Sha256Digest,
}

impl ContextTextChunk {
    pub fn source(&self) -> &SourceIdentity {
        &self.source
    }

    pub const fn range(&self) -> LineRange {
        self.range
    }

    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Utf8Chunker {
    max_bytes: usize,
}

impl Utf8Chunker {
    pub fn new(max_bytes: usize) -> Result<Self, PortError> {
        if max_bytes == 0 || max_bytes > 1024 * 1024 {
            return Err(invalid());
        }
        Ok(Self { max_bytes })
    }

    pub fn chunk(&self, source: &ContextTextSource) -> Result<Vec<ContextTextChunk>, PortError> {
        let text = std::str::from_utf8(&source.bytes).map_err(|_| invalid())?;
        let lines = text.split_inclusive('\n').collect::<Vec<_>>();
        let mut chunks = Vec::new();
        let mut current = String::new();
        let mut start_line = 1u32;
        let mut end_line = 0u32;

        for (index, line) in lines.iter().enumerate() {
            let line_number = u32::try_from(index + 1).map_err(|_| invalid())?;
            if line.len() > self.max_bytes {
                if !current.is_empty() {
                    chunks.push(make_chunk(source, start_line, end_line, current)?);
                    current = String::new();
                }
                let mut remaining = *line;
                while !remaining.is_empty() {
                    let split = utf8_split_boundary(remaining, self.max_bytes)?;
                    let (part, rest) = remaining.split_at(split);
                    chunks.push(make_chunk(
                        source,
                        line_number,
                        line_number,
                        part.to_owned(),
                    )?);
                    remaining = rest;
                }
                start_line = line_number.saturating_add(1);
                end_line = line_number;
                continue;
            }
            if !current.is_empty() && current.len().saturating_add(line.len()) > self.max_bytes {
                chunks.push(make_chunk(source, start_line, end_line, current)?);
                current = String::new();
                start_line = line_number;
            }
            current.push_str(line);
            end_line = line_number;
            if line.trim().is_empty() && !current.is_empty() {
                chunks.push(make_chunk(source, start_line, end_line, current)?);
                current = String::new();
                start_line = line_number.saturating_add(1);
            }
        }
        if !current.is_empty() {
            chunks.push(make_chunk(source, start_line, end_line, current)?);
        }
        if chunks.is_empty() {
            return Err(invalid());
        }
        Ok(chunks)
    }
}

fn utf8_split_boundary(value: &str, max_bytes: usize) -> Result<usize, PortError> {
    let mut split = value.len().min(max_bytes);
    while split > 0 && !value.is_char_boundary(split) {
        split -= 1;
    }
    if split == 0 {
        Err(invalid())
    } else {
        Ok(split)
    }
}

fn make_chunk(
    source: &ContextTextSource,
    start: u32,
    end: u32,
    content: String,
) -> Result<ContextTextChunk, PortError> {
    let bytes = content.into_bytes();
    Ok(ContextTextChunk {
        source: source.identity.clone(),
        range: LineRange::new(start, end).map_err(|_| invalid())?,
        language: source.language.clone(),
        symbol: source.symbol.clone(),
        content_digest: digest(&bytes),
        bytes,
    })
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is valid")
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1_024 && !value.contains('\0')
}

fn invalid() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use local_agent_terminal_domain::ProjectId;

    #[test]
    fn chunks_on_paragraph_and_line_boundaries_without_changing_source_identity() {
        let bytes = b"one\ntwo\n\nthree\nfour\n".to_vec();
        let identity = SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            "src/lib.rs",
            digest(&bytes),
        )
        .unwrap();
        let source = ContextTextSource::new(identity.clone(), Some("rust"), None, bytes).unwrap();

        let chunks = Utf8Chunker::new(9).unwrap().chunk(&source).unwrap();

        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|chunk| chunk.bytes().len() <= 9));
        assert!(chunks.iter().all(|chunk| chunk.source() == &identity));
        assert_eq!(chunks[0].range(), LineRange::new(1, 3).unwrap());
        assert_eq!(chunks[1].range(), LineRange::new(4, 4).unwrap());
        assert_eq!(chunks[2].range(), LineRange::new(5, 5).unwrap());
    }

    #[test]
    fn splits_long_lines_at_utf8_boundaries_without_losing_provenance() {
        let bytes = "é".repeat(7).into_bytes();
        let identity = SourceIdentity::new(
            ProjectId::new("project-1").unwrap(),
            "commit-1",
            "src/lib.rs",
            digest(&bytes),
        )
        .unwrap();
        let source = ContextTextSource::new(identity, Some("rust"), None, bytes.clone()).unwrap();

        let chunks = Utf8Chunker::new(5).unwrap().chunk(&source).unwrap();

        assert!(chunks.iter().all(|chunk| chunk.bytes().len() <= 5));
        assert!(chunks
            .iter()
            .all(|chunk| chunk.range() == LineRange::new(1, 1).unwrap()));
        assert_eq!(
            chunks
                .iter()
                .flat_map(|chunk| chunk.bytes().iter().copied())
                .collect::<Vec<_>>(),
            bytes
        );
    }
}
