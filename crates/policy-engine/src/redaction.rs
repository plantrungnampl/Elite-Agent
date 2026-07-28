use crate::{invalid_input, sha256_digest, PortError, Sha256Digest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionEntry {
    pub category: String,
    pub start: usize,
    pub end: usize,
    pub replacement_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionReport {
    pub entries: Vec<RedactionEntry>,
    pub digest: Sha256Digest,
}

pub(crate) fn redact(bytes: &[u8]) -> Result<(Vec<u8>, RedactionReport), PortError> {
    let matches = scan(bytes);
    let mut effective = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    let mut entries = Vec::with_capacity(matches.len());
    for matched in matches {
        effective.extend_from_slice(&bytes[cursor..matched.start]);
        let replacement = replacement(&matched.category, &bytes[matched.start..matched.end]);
        effective.extend_from_slice(replacement.as_bytes());
        entries.push(RedactionEntry {
            category: matched.category,
            start: matched.start,
            end: matched.end,
            replacement_digest: Sha256Digest::new(sha256_digest(replacement.as_bytes()))
                .map_err(|_| invalid_input())?,
        });
        cursor = matched.end;
    }
    effective.extend_from_slice(&bytes[cursor..]);
    let report_value = entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "category": entry.category,
                "start": entry.start,
                "end": entry.end,
                "replacementDigest": entry.replacement_digest.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let canonical = serde_json_canonicalizer::to_vec(&report_value).map_err(|_| invalid_input())?;
    let digest = Sha256Digest::new(sha256_digest(&canonical)).map_err(|_| invalid_input())?;
    Ok((effective, RedactionReport { entries, digest }))
}

pub(crate) fn scan(bytes: &[u8]) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    find_line_value(bytes, b"API_TOKEN=", "api_token", &mut matches);
    find_token(bytes, b"tok_test_", "api_token", &mut matches);
    find_line_value_ascii_case_insensitive(
        bytes,
        b"postgresql://",
        "connection_string",
        &mut matches,
    );
    find_between(
        bytes,
        b"-----BEGIN PRIVATE KEY-----",
        b"-----END PRIVATE KEY-----",
        "private_key",
        &mut matches,
    );
    find_line_value_ascii_case_insensitive(
        bytes,
        b"postgres://",
        "connection_string",
        &mut matches,
    );
    find_literal(bytes, b".env", "secret_filename", &mut matches);
    find_literal(bytes, b"secrets.zip", "archive_metadata", &mut matches);
    find_line_value(
        bytes,
        b"classification=",
        "restricted_classification",
        &mut matches,
    );
    find_literal(
        bytes,
        b"ignore prior instructions",
        "prompt_injection",
        &mut matches,
    );
    normalize_matches(matches)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecretMatch {
    pub category: String,
    pub start: usize,
    pub end: usize,
}

fn find_line_value(bytes: &[u8], prefix: &[u8], category: &str, matches: &mut Vec<SecretMatch>) {
    let mut offset = 0;
    while let Some(found) = find(bytes, prefix, offset) {
        let end = bytes[found..]
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
            .map_or(bytes.len(), |index| found + index);
        matches.push(SecretMatch {
            category: category.to_owned(),
            start: found,
            end,
        });
        offset = end.max(found + 1);
    }
}

fn find_line_value_ascii_case_insensitive(
    bytes: &[u8],
    prefix: &[u8],
    category: &str,
    matches: &mut Vec<SecretMatch>,
) {
    let mut offset = 0;
    while let Some(found) = find_ascii_case_insensitive(bytes, prefix, offset) {
        let end = bytes[found..]
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))
            .map_or(bytes.len(), |index| found + index);
        matches.push(SecretMatch {
            category: category.to_owned(),
            start: found,
            end,
        });
        offset = end.max(found + 1);
    }
}

fn find_between(
    bytes: &[u8],
    start_marker: &[u8],
    end_marker: &[u8],
    category: &str,
    matches: &mut Vec<SecretMatch>,
) {
    let mut offset = 0;
    while let Some(start) = find(bytes, start_marker, offset) {
        let after_start = start + start_marker.len();
        let Some(end_start) = find(bytes, end_marker, after_start) else {
            matches.push(SecretMatch {
                category: category.to_owned(),
                start,
                end: bytes.len(),
            });
            return;
        };
        let end = end_start + end_marker.len();
        matches.push(SecretMatch {
            category: category.to_owned(),
            start,
            end,
        });
        offset = end;
    }
}

fn find_token(bytes: &[u8], prefix: &[u8], category: &str, matches: &mut Vec<SecretMatch>) {
    let mut offset = 0;
    while let Some(start) = find(bytes, prefix, offset) {
        let end = bytes[start..]
            .iter()
            .position(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
            .map_or(bytes.len(), |index| start + index);
        matches.push(SecretMatch {
            category: category.to_owned(),
            start,
            end,
        });
        offset = end.max(start + 1);
    }
}

fn find_literal(bytes: &[u8], needle: &[u8], category: &str, matches: &mut Vec<SecretMatch>) {
    let mut offset = 0;
    while let Some(start) = find(bytes, needle, offset) {
        let end = start + needle.len();
        matches.push(SecretMatch {
            category: category.to_owned(),
            start,
            end,
        });
        offset = end;
    }
}

fn find(bytes: &[u8], needle: &[u8], offset: usize) -> Option<usize> {
    bytes[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| offset + index)
}

fn find_ascii_case_insensitive(bytes: &[u8], needle: &[u8], offset: usize) -> Option<usize> {
    bytes[offset..]
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
        .map(|index| offset + index)
}

fn normalize_matches(mut matches: Vec<SecretMatch>) -> Vec<SecretMatch> {
    matches.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
            .then_with(|| left.category.cmp(&right.category))
    });
    let mut normalized = Vec::new();
    for matched in matches {
        if normalized
            .last()
            .is_some_and(|previous: &SecretMatch| matched.start < previous.end)
        {
            continue;
        }
        normalized.push(matched);
    }
    normalized
}

fn replacement(category: &str, original: &[u8]) -> String {
    let digest = sha256_digest(original);
    format!("[REDACTED:{category}:{}]", &digest[7..23])
}
