//! One RESULT reader on the original Supervisor IO roster. It publishes only
//! validated control + its original Instant early; EOF/joins still own finality.
use super::*;

struct Framer { frame: PrivateBytes, complete: bool }
impl Framer {
    fn new() -> Result<Self, BridgeError> {
        let mut bytes = Vec::new(); bytes.try_reserve_exact(runner_protocol::RESPONSE_LIMIT).map_err(|_| BridgeError::protocol())?;
        if bytes.capacity() > runner_protocol::RESPONSE_LIMIT { return Err(BridgeError::protocol()); }
        Ok(Self { frame: PrivateBytes(bytes), complete: false })
    }
    fn byte(&mut self, byte: u8, id: &str) -> Result<Option<github_protocol::GitHubReadControl>, BridgeError> {
        if self.complete { return Err(BridgeError::protocol()); }
        if self.frame.len() >= runner_protocol::RESPONSE_LIMIT {
            return Err(BridgeError::new("stdout_limit", "The runner-safety response exceeded its fixed byte allowance."));
        }
        self.frame.push(byte);
        if byte != b'\n' { return Ok(None); }
        let reply = runner_protocol::decode_reply(id, &self.frame)?;
        self.complete = true;
        Ok(Some(reply.control))
    }
    fn finish(&self) -> Result<(), BridgeError> { if self.complete { Ok(()) } else { Err(BridgeError::protocol()) } }
}
pub(super) async fn read<R: AsyncRead + Unpin>(mut reader: R, owner: Arc<Owner>) -> ReadEnd {
    if !matches!(owner.profile, Profile::GitHubRunnerPrerequisite) || owner.runner_receipt.is_none() {
        owner.fail(BridgeError::cleanup_unknown()); return ReadEnd { bytes: Vec::new(), eof: false, overflow: false };
    }
    let mut framer = match Framer::new() {
        Ok(value) => value, Err(error) => { owner.fail(error); return ReadEnd { bytes: Vec::new(), eof: false, overflow: false }; },
    };
    let mut buffer = PrivateBytes(vec![0u8;8192]); let mut failed = false; let mut overflow = false;
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(0) => {
                if !failed { if let Err(error) = framer.finish() { owner.fail(error); } }
                return ReadEnd { bytes: std::mem::take(&mut framer.frame.0), eof: true, overflow };
            },
            Ok(count) => count,
            Err(_) => { owner.fail(BridgeError::new("io_error", "The original runner-safety output channel failed."));
                return ReadEnd { bytes: std::mem::take(&mut framer.frame.0), eof: false, overflow }; },
        };
        // A malformed/extra byte latches failure immediately; drain/discard only
        // this same original pipe. No replacement reader, clock, retry or join.
        if failed { continue; }
        for byte in &buffer[..count] {
            match framer.byte(*byte, &owner.id) {
                Ok(None) => {},
                Ok(Some(control)) => {
                    let mut observed = lock(&owner.runner_control);
                    if observed.is_some() { drop(observed); owner.fail(BridgeError::protocol()); failed = true; break; }
                    *observed = Some(GitHubRunnerObservedControl { control, observed_at: Instant::now() });
                    drop(observed); owner.changed.notify_waiters();
                },
                Err(error) => { overflow = error.code == "stdout_limit"; owner.fail(error); failed = true; break; },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_result_control_is_available_before_eof_but_trailing_data_refuses() {
        let raw = format!("{{\"protocol\":\"{}\",\"id\":\"runner-1\",\"result\":{{\"schemaVersion\":1,\"reason\":\"rate-limited\",\"facts\":null,\"control\":{{\"reason\":\"rate-limited\",\"credentialExpiresAt\":null,\"cooldownSeconds\":7,\"cooldownBlocked\":false}},\"networkCleanup\":\"confirmed\"}}}}\n", runner_protocol::PROTOCOL);
        let mut framer = Framer::new().unwrap(); let mut controls = Vec::new();
        for byte in raw.bytes() { if let Some(control) = framer.byte(byte,"runner-1").unwrap() { controls.push(control); } }
        assert_eq!(controls.len(),1); assert_eq!(controls[0].cooldown_seconds,Some(7));
        assert!(framer.finish().is_ok()); assert!(framer.byte(b' ',"runner-1").is_err());
        let mut incomplete = Framer::new().unwrap();
        for byte in raw.bytes().take(raw.len()-1) { assert!(incomplete.byte(byte,"runner-1").unwrap().is_none()); }
        assert!(incomplete.finish().is_err());
        // These are framing DATA only, not native EOF or an original receipt.
    }
}
