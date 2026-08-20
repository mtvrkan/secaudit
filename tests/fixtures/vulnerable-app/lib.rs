// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
use std::mem;
use std::process::Command;

// V37 — `unsafe` block with no safety justification (CWE-758): the invariants that make it
// sound are not written down, so nobody can check them at review time.
pub fn first_byte(data: &[u8]) -> u8 {
    unsafe {
        *data.get_unchecked(0)
    }
}

// V38 — `mem::transmute` reinterprets bytes with no checks (CWE-704): a layout the compiler
// does not verify is assumed to hold.
pub fn as_floats(raw: [u8; 4]) -> f32 {
    unsafe { mem::transmute::<[u8; 4], f32>(raw) }
}

// V39 — Shell interpreter re-introduced (CWE-78): `sh -c` puts metacharacter injection back
// into a language that otherwise avoids it.
pub fn run(label: &str) {
    let _ = Command::new("sh").arg("-c").arg(format!("report --for {}", label)).status();
}
