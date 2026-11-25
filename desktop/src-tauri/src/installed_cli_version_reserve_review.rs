//! Source review only. No Store query, candidate, counter or Reserve consent.
use super::*;
use crate::service_version_reserve_review_protocol as review;
pub(super) fn options(bytes: &[u8]) -> Result<review::Options, Error> {
    if bytes.is_empty() || bytes.len() > 512 {
        return Err(Error::InvalidRequest);
    }
    let v: review::Options = serde_json::from_slice(bytes).map_err(|_| Error::InvalidRequest)?;
    if !v.valid() {
        return Err(Error::InvalidRequest);
    }
    Ok(v)
}
pub(super) fn stdin_options() -> Result<review::Options, Error> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(513)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    options(&bytes)
}
pub(super) fn output(
    response: &p::Response,
    q: &reserve::Query,
    json: bool,
) -> Result<(u8, Vec<u8>), Error> {
    let p::ResponseBody::VersionReserveReview(s) = &response.response else {
        return Err(Error::StateUnknown);
    };
    s.validate()?;
    if s.origin != *q || response.service_instance != q.service_instance {
        return Err(Error::StateUnknown);
    }
    let code = match s.phase {
        review::Phase::Unknown => 6,
        review::Phase::Refused => 5,
        _ => 0,
    };
    let bytes = if json {
        let mut b = p::encode_response(response)?;
        b.push(b'\n');
        b
    } else {
        format!("Version source review: {:?}; {:?}.\n{}Review only: no number reserved and no Store request made. Use the separate explicit Desktop Allow once, then version-reserve-submit with its exact Review/grant IDs. Counter setup and enrollment remain separate.\n",s.phase,s.settlement,receipt(q)).into_bytes()
    };
    Ok((code, bytes))
}
#[cfg(test)]
#[path = "installed_cli_version_reserve_review_tests.rs"]
mod tests;
