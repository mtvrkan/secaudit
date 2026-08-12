// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
use std::process::Command;

// S37 — Bounds are checked, so no `unsafe` is needed at all (CWE-758 fixed). The safest
// unsafe block is the one that does not exist.
pub fn first_byte(data: &[u8]) -> Option<u8> {
    data.first().copied()
}

// S38 — Checked conversion (CWE-704 fixed): `from_le_bytes` states the layout explicitly and
// the compiler verifies the size, instead of asserting a reinterpretation is valid.
pub fn as_floats(raw: [u8; 4]) -> f32 {
    f32::from_le_bytes(raw)
}

// S39 — Program invoked directly (CWE-78 fixed): arguments are passed as an array, so no
// shell parses them and metacharacters are just characters.
pub fn run(label: &str) {
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return;
    }
    let _ = Command::new("report").arg("--for").arg(label).status();
}
