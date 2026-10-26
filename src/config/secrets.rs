
use anyhow::{Result, anyhow};
use camino::Utf8Path;

// Format:
//
//    MY_PROVIDER_KEY=pk1_d1hvj29L0Og+vdpSisTpWYBCfyDCl7fGp0UMOSdFxrI
//    MY_PROVIDER_SECRET = sk1_DMWjszfASDFNvK+I8hjJgLJIR2TpwSqLWMqbKY8Yts0
//
// TODO: Ideally these should be read as-needed (primarily in acme.rs
// for DNS updates) and then overwritten (avoiding row-hammer/spectre
// secret-extraction vulns), but currently these are cloned in various
// places so this isn't practical.
pub fn read_secret(file: &Utf8Path, name: &str) -> Result<String> {
    println!("PWD: {:?}", std::env::current_dir());
    let contents = std::fs::read(file)?;

    for line in contents.split(|&c| c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if let Some(i) = line.iter().position(|&c| c == b'=') {
            let (k, v) = line.split_at(i);
            let k = k.trim_ascii();
            let v = v[1..].trim_ascii();

            if k == name.as_bytes() {
                let v = str::from_utf8(v)?;
                return Ok(v.to_string())
            }
        }
    }

    Err(anyhow!("Key {name} not found in {file}"))
}
