//! Fixed public SOURCE configuration for the producer verifier's generated C
//! header. This proves only closed shape and source-policy correspondence.
//! The native verifier MUST still recompute every DER digest, parse all three
//! certificates, check the returned public key and evaluate the fixed trust
//! policy. A generated CONFIGURED1 header is not authentication or readiness.
#![forbid(unsafe_code)]

use std::fmt::Write;

pub const PROFILE_LIMIT: usize = 1024;
pub const SERVICE_PROFILE_LIMIT: usize = 512;
pub const CERTIFICATE_LIMIT: usize = 16 * 1024;
pub const HEADER_LIMIT: usize = 320 * 1024;
pub const UNCONFIGURED_HEADER: &str = "/* Fixed SOURCE selection; no runtime/ambient identity. */\n#define MRK_INSTALL_PRODUCER_CONFIGURED 0\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceError { Limit, Shape, Service, Correspondence, Certificates, Header }
type Result<T> = std::result::Result<T, SourceError>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pins {
    team: [u8; 10],
    rsa_bits: u32,
    leaf_sha1: [u8; 20],
    leaf_sha256: [u8; 32],
    issuer_sha256: [u8; 32],
    root_sha256: [u8; 32],
    public_key_sha256: [u8; 32],
}

/// Build-only DATA. Private fields prevent construction from an observed
/// package, environment variable or an arbitrary generated-header string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSelection { pins: Option<Pins> }

fn lines(bytes: &[u8], limit: usize) -> Result<Vec<&str>> {
    if bytes.is_empty() || bytes.len() > limit { return Err(SourceError::Limit); }
    if !bytes.iter().all(|byte| *byte == b'\n' || (0x21..=0x7e).contains(byte)) {
        return Err(SourceError::Shape);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SourceError::Shape)?;
    let body = text.strip_suffix('\n').ok_or(SourceError::Shape)?;
    let rows: Vec<_> = body.split('\n').collect();
    if rows.iter().any(|row| row.is_empty()) { return Err(SourceError::Shape); }
    Ok(rows)
}

fn value<'a>(row: &'a str, name: &str) -> Result<&'a str> {
    row.strip_prefix(name).filter(|value| !value.is_empty()).ok_or(SourceError::Shape)
}

fn team(value: &str) -> Result<[u8; 10]> {
    if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()) {
        return Err(SourceError::Shape);
    }
    value.as_bytes().try_into().map_err(|_| SourceError::Shape)
}

fn hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 { return Err(SourceError::Shape); }
    let mut out = [0; N];
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SourceError::Shape),
    };
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    if out.iter().all(|byte| *byte == 0) { return Err(SourceError::Shape); }
    Ok(out)
}

// The existing app/service requirements remain the SOURCE identity. A second
// profile cannot silently configure a different descriptor signer.
fn service_identity(bytes: &[u8]) -> Result<Option<([u8; 10], [u8; 20])>> {
    let rows = lines(bytes, SERVICE_PROFILE_LIMIT)?;
    if rows.len() != 5 || rows[0] != "schema=1"
        || rows[1] != "app-identifier=dev.mobile-release-kit.desktop"
        || rows[2] != "helper-identifier=dev.mobile-release-kit.desktop.android-register" {
        return Err(SourceError::Service);
    }
    let team_value = value(rows[3], "team-identifier=")?;
    let leaf_value = value(rows[4], "developer-id-certificate-sha1=")?;
    if team_value == "unconfigured" && leaf_value == "unconfigured" { return Ok(None); }
    Ok(Some((team(team_value)?, hex(leaf_value)?)))
}

impl SourceSelection {
    pub fn parse(profile: &[u8], service_profile: &[u8]) -> Result<Self> {
        let rows = lines(profile, PROFILE_LIMIT)?;
        let service = service_identity(service_profile)?;
        if rows.as_slice() == ["schema=1", "state=unconfigured"] {
            return Ok(Self { pins: None });
        }
        if rows.len() != 9 || rows[0] != "schema=1" || rows[1] != "state=configured" {
            return Err(SourceError::Shape);
        }
        let pins = Pins {
            team: team(value(rows[2], "team-identifier=")?)?,
            rsa_bits: match value(rows[3], "rsa-bits=")? {
                "2048" => 2048, "3072" => 3072, "4096" => 4096,
                _ => return Err(SourceError::Shape),
            },
            leaf_sha1: hex(value(rows[4], "leaf-certificate-sha1=")?)?,
            leaf_sha256: hex(value(rows[5], "leaf-certificate-sha256=")?)?,
            issuer_sha256: hex(value(rows[6], "issuer-certificate-sha256=")?)?,
            root_sha256: hex(value(rows[7], "root-certificate-sha256=")?)?,
            public_key_sha256: hex(value(rows[8], "public-key-pkcs1-sha256=")?)?,
        };
        if service != Some((pins.team, pins.leaf_sha1))
            || pins.leaf_sha256 == pins.issuer_sha256 || pins.leaf_sha256 == pins.root_sha256
            || pins.issuer_sha256 == pins.root_sha256 {
            return Err(SourceError::Correspondence);
        }
        Ok(Self { pins: Some(pins) })
    }

    pub fn requires_certificates(&self) -> bool { self.pins.is_some() }

    pub fn header(&self, certificates: Option<[&[u8]; 3]>) -> Result<String> {
        let Some(pins) = self.pins.as_ref() else {
            if certificates.is_some() { return Err(SourceError::Certificates); }
            return Ok(UNCONFIGURED_HEADER.to_owned());
        };
        let certificates = certificates.ok_or(SourceError::Certificates)?;
        if certificates.iter().any(|bytes| bytes.is_empty() || bytes.len() > CERTIFICATE_LIMIT)
            || certificates[0] == certificates[1] || certificates[0] == certificates[2]
            || certificates[1] == certificates[2] {
            return Err(SourceError::Certificates);
        }
        let mut out = String::with_capacity(HEADER_LIMIT);
        out.push_str("/* Public SOURCE shape only; native digest/key/trust validation is mandatory. */\n#define MRK_INSTALL_PRODUCER_CONFIGURED 1\n");
        writeln!(out, "#define MRK_INSTALL_PRODUCER_RSA_BITS {}", pins.rsa_bits).map_err(|_| SourceError::Header)?;
        for (role, bytes) in ["leaf", "issuer", "root"].into_iter().zip(certificates) {
            array(&mut out, &format!("mrk_install_producer_{role}_der"), bytes)?;
        }
        for (name, bytes) in [
            ("leaf_sha1", pins.leaf_sha1.as_slice()),
            ("leaf_sha256", pins.leaf_sha256.as_slice()),
            ("issuer_sha256", pins.issuer_sha256.as_slice()),
            ("root_sha256", pins.root_sha256.as_slice()),
            ("public_key_pkcs1_sha256", pins.public_key_sha256.as_slice()),
        ] { array(&mut out, &format!("mrk_install_producer_{name}"), bytes)?; }
        let mut terminated_team = [0; 11];
        terminated_team[..10].copy_from_slice(&pins.team);
        array(&mut out, "mrk_install_producer_team", &terminated_team)?;
        if out.len() > HEADER_LIMIT { return Err(SourceError::Header); }
        Ok(out)
    }
}

fn array(out: &mut String, name: &str, bytes: &[u8]) -> Result<()> {
    // Names are fixed local literals; all input values become numeric bytes.
    writeln!(out, "static const uint8_t {name}[{}] = {{", bytes.len()).map_err(|_| SourceError::Header)?;
    for chunk in bytes.chunks(16) {
        out.push_str("    ");
        for byte in chunk { write!(out, "0x{byte:02x},").map_err(|_| SourceError::Header)?; }
        out.push('\n');
    }
    out.push_str("};\n");
    if out.len() > HEADER_LIMIT { return Err(SourceError::Header); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNCONFIGURED: &[u8] = b"schema=1\nstate=unconfigured\n";
    fn service(configured: bool) -> String {
        format!("schema=1\napp-identifier=dev.mobile-release-kit.desktop\nhelper-identifier=dev.mobile-release-kit.desktop.android-register\nteam-identifier={}\ndeveloper-id-certificate-sha1={}\n",
            if configured { "TEAM000001" } else { "unconfigured" },
            if configured { "1".repeat(40) } else { "unconfigured".to_owned() })
    }
    fn profile(bits: u32) -> String {
        format!("schema=1\nstate=configured\nteam-identifier=TEAM000001\nrsa-bits={bits}\nleaf-certificate-sha1={}\nleaf-certificate-sha256={}\nissuer-certificate-sha256={}\nroot-certificate-sha256={}\npublic-key-pkcs1-sha256={}\n",
            "1".repeat(40), "2".repeat(64), "3".repeat(64), "4".repeat(64), "5".repeat(64))
    }

    #[test]
    fn fixed_source_selection_requires_complete_matching_identity_and_no_ambient_default() {
        let unconfigured = service(false); let configured = service(true);
        for service in [&unconfigured, &configured] {
            let data = SourceSelection::parse(UNCONFIGURED, service.as_bytes()).unwrap();
            assert!(!data.requires_certificates());
            assert_eq!(data.header(None).unwrap(), UNCONFIGURED_HEADER);
            assert_eq!(data.header(Some([b"a", b"b", b"c"])), Err(SourceError::Certificates));
        }
        let good = profile(2048);
        assert_eq!(SourceSelection::parse(good.as_bytes(), unconfigured.as_bytes()), Err(SourceError::Correspondence));
        for bad in [String::new(), good.trim_end().to_owned(), format!("{good}\n"),
            good.replace("state=configured", "state=unconfigured"),
            good.replace("rsa-bits=2048", "rsa-bits=8192"),
            good.replace("rsa-bits=2048", "rsa-bits=02048"),
            good.replace("team-identifier=TEAM000001", "team-identifier=OTHER00001"),
            good.replace("team-identifier=TEAM000001", "team-identifier=lowercase1"),
            good.replace("leaf-certificate-sha1=", "leaf-certificate-sha1=0"),
            good.replace(&"2".repeat(64), &"0".repeat(64)),
            good.replace(&"2".repeat(64), &"A".repeat(64)),
            good.replace(&"2".repeat(64), &"3".repeat(64)),
            good.replace("\n", "\r\n"), format!("{good}other=1\n"),
            good.replace("rsa-bits=2048", "rsa-bits=2048\nrsa-bits=2048"),
            good.replace("state=configured", "state=configured\0"),
            "x".repeat(PROFILE_LIMIT + 1)] {
            assert!(SourceSelection::parse(bad.as_bytes(), configured.as_bytes()).is_err());
        }
        for bad in [configured.replace("app-identifier=dev.mobile-release-kit.desktop", "app-identifier=foreign"),
            configured.replace("team-identifier=TEAM000001", "team-identifier=OTHER00001"),
            configured.replace(&"1".repeat(40), &"6".repeat(40)),
            configured.replace("team-identifier=TEAM000001", "team-identifier=unconfigured"),
            configured.replace("schema=1", "schema=2"), format!("{configured}extra=value\n")] {
            assert!(SourceSelection::parse(good.as_bytes(), bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn configured_header_contains_only_bounded_fixed_byte_arrays_and_is_not_trust_evidence() {
        let configured = service(true);
        // Explicit invalid synthetic bytes: this tests C-source encoding, NOT
        // DER parsing, a genuine certificate chain or native authentication.
        let leaf = b"\x30\x01\x01\"\n#include <bad>";
        let issuer = b"\x30\x01\x02"; let root = b"\x30\x01\x03";
        for bits in [2048, 3072, 4096] {
            let data = SourceSelection::parse(profile(bits).as_bytes(), configured.as_bytes()).unwrap();
            assert!(data.requires_certificates());
            assert_eq!(data.header(None), Err(SourceError::Certificates));
            for certs in [[b"".as_slice(), issuer, root], [leaf, leaf, root], [leaf, issuer, issuer]] {
                assert_eq!(data.header(Some(certs)), Err(SourceError::Certificates));
            }
            let header = data.header(Some([leaf, issuer, root])).unwrap();
            assert!(header.contains("#define MRK_INSTALL_PRODUCER_CONFIGURED 1\n"));
            assert!(header.contains(&format!("#define MRK_INSTALL_PRODUCER_RSA_BITS {bits}\n")));
            assert!(header.contains("static const uint8_t mrk_install_producer_team[11]"));
            assert!(header.contains("static const uint8_t mrk_install_producer_leaf_sha1[20]"));
            assert!(header.contains("static const uint8_t mrk_install_producer_public_key_pkcs1_sha256[32]"));
            assert!(!header.contains("#include <bad>"));
            assert_eq!(header.matches("static const uint8_t ").count(), 9);
        }
        let data = SourceSelection::parse(profile(2048).as_bytes(), configured.as_bytes()).unwrap();
        let a = vec![1; CERTIFICATE_LIMIT]; let b = vec![2; CERTIFICATE_LIMIT];
        let c = vec![3; CERTIFICATE_LIMIT];
        assert!(data.header(Some([&a, &b, &c])).unwrap().len() <= HEADER_LIMIT);
        let too_large = vec![1; CERTIFICATE_LIMIT + 1];
        assert_eq!(data.header(Some([&too_large, &b, &c])), Err(SourceError::Certificates));
    }
}
