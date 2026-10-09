use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

/// Preserve normal child exits and report signal termination using shell convention.
pub fn shell_exit_code(status: ExitStatus) -> u8 {
    status
        .code()
        .unwrap_or_else(|| status.signal().map_or(1, |signal| 128 + signal)) as u8
}

#[cfg(test)]
mod tests {
    use super::shell_exit_code;
    use std::process::Command;

    #[test]
    fn preserves_normal_child_exit_codes() {
        for code in [0, 7, 127, 255] {
            let status = Command::new("sh")
                .args(["-c", &format!("exit {code}")])
                .status()
                .unwrap();
            assert_eq!(shell_exit_code(status), code);
        }
    }

    #[test]
    fn signal_termination_is_not_reported_as_success() {
        let status = Command::new("sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert_eq!(shell_exit_code(status), 143);
    }
}
