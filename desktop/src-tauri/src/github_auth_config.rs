//! Closed, allocation-free schema-one recognizer; not a YAML parser/writer.
//! Exact upstream contract and matching finite Python grammar are documented
//! in _desktop_github_auth_config.py. Caller supplies actual held PRIVATE bytes.
const ROOT_KEYS: [&[u8]; 13] = [
    b"version",
    b"git_protocol",
    b"editor",
    b"prompt",
    b"prefer_editor_prompt",
    b"pager",
    b"aliases",
    b"http_unix_socket",
    b"browser",
    b"color_labels",
    b"accessible_colors",
    b"accessible_prompter",
    b"spinner",
];
const MAX_BYTES: usize = 65536;
const MAX_LINES: usize = 256;
const MAX_ALIASES: usize = 64;

fn trim(raw: &[u8]) -> &[u8] {
    let start = raw.iter().position(|c| *c != b' ').unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|c| *c != b' ')
        .map_or(start, |i| i + 1);
    &raw[start..end]
}
fn scalar(raw: &[u8]) -> Option<&[u8]> {
    let raw = trim(raw);
    if raw.is_empty() || raw.starts_with(b"#") {
        return Some(b"");
    }
    if matches!(raw[0], b'\'' | b'"') {
        let end = raw[1..].iter().position(|c| *c == raw[0])? + 1;
        let tail = &raw[end + 1..];
        if !tail.is_empty() && (!tail.starts_with(b" ") || !trim(tail).starts_with(b"#")) {
            return None;
        }
        let value = &raw[1..end];
        return (!value.iter().any(|c| matches!(*c, b'\\' | b'\'' | b'"'))).then_some(value);
    }
    let end = raw.windows(2).position(|c| c == b" #").unwrap_or(raw.len());
    let value = trim(&raw[..end]);
    (!value.is_empty()
        && !matches!(value[0], b'-' | b'+')
        && value
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b" _./=+-".contains(c)))
    .then_some(value)
}

pub(crate) fn schema_one(raw: &[u8]) -> bool {
    if raw.is_empty()
        || raw.len() > MAX_BYTES
        || raw
            .iter()
            .any(|c| !matches!(*c, b'\n' | b'\r') && !(32..=126).contains(c))
    {
        return false;
    }
    let mut roots = 0u16;
    let mut aliases: [Option<&[u8]>; MAX_ALIASES] = [None; MAX_ALIASES];
    let (mut in_aliases, mut alias_indent, mut found) = (false, None, false);
    let mut alias_count = 0usize;
    for (line, raw_row) in raw.split(|c| *c == b'\n').enumerate() {
        if line >= MAX_LINES {
            return false;
        }
        let row = raw_row.strip_suffix(b"\r").unwrap_or(raw_row);
        if row.contains(&b'\r') {
            return false;
        }
        let indent = row.iter().position(|c| *c != b' ').unwrap_or(row.len());
        let text = &row[indent..];
        if text.is_empty() || text.starts_with(b"#") {
            continue;
        }
        let Some(colon) = text.iter().position(|c| *c == b':') else {
            return false;
        };
        let (key, rest) = (&text[..colon], &text[colon + 1..]);
        if !rest.is_empty() && !rest.starts_with(b" ") {
            return false;
        }
        if indent == 0 {
            let Some(index) = ROOT_KEYS.iter().position(|known| *known == key) else {
                return false;
            };
            if roots & (1u16 << index) != 0 {
                return false;
            }
            roots |= 1u16 << index;
            in_aliases = key == b"aliases";
            alias_indent = None;
        } else {
            if !in_aliases
                || !matches!(indent, 2 | 4)
                || alias_indent.is_some_and(|value| value != indent)
                || key.is_empty()
                || key.len() > 64
                || !key
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(c))
                || alias_count == MAX_ALIASES
                || aliases[..alias_count].contains(&Some(key))
            {
                return false;
            }
            alias_indent = Some(indent);
            aliases[alias_count] = Some(key);
            alias_count += 1;
        }
        let Some(value) = scalar(rest) else {
            return false;
        };
        if indent == 0
            && key == b"aliases"
            && !trim(rest).is_empty()
            && !trim(rest).starts_with(b"#")
        {
            return false;
        }
        if indent == 0 && key == b"version" {
            if value != b"1" {
                return false;
            }
            found = true;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_native_python_closed_schema_cases_data_only() {
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            text: String,
            accepted: bool,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/gh_auth_schema_one.json"
        )))
        .unwrap();
        assert_eq!(cases.len(), 50);
        for case in cases {
            assert_eq!(
                schema_one(case.text.as_bytes()),
                case.accepted,
                "{}",
                case.name
            );
        }
    }
    #[test]
    fn bounded_private_config_lines_aliases_and_raw_bytes_data_only() {
        assert!(!schema_one(
            &[b"version: 1\n".as_slice(), &vec![b'#'; MAX_BYTES]].concat()
        ));
        assert!(!schema_one(
            &[b"version: 1\n".as_slice(), &vec![b'\n'; MAX_LINES]].concat()
        ));
        let mut aliases = String::from("version: 1\naliases:\n");
        for i in 0..65 {
            aliases.push_str(&format!("  a{i}: fixture\n"));
        }
        assert!(!schema_one(aliases.as_bytes()));
        assert!(!schema_one(b"version: 1\neditor: \xff\n"));
    }
}
