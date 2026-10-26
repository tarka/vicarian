
use anyhow::{Result, anyhow};
use camino::Utf8Path;
use zeroize::Zeroize;

pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}


#[derive(Debug)]
struct Secrets(Vec<u8>);

impl Drop for Secrets {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}


// Format:
//
//    MY_PROVIDER_KEY=pk1_d1hvj29L0Og+vdpSisTpWYBCfyDCl7fGp0UMOSdFxrI
//    MY_PROVIDER_SECRET = sk1_DMWjszfASDFNvK+I8hjJgLJIR2TpwSqLWMqbKY8Yts0
//
pub async fn read_secret(file: &Utf8Path, name: &str) -> Result<Secret> {
    let contents = Secrets(tokio::fs::read(file).await?);

    for line in contents.0.split(|&c| c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        if let Some(i) = line.iter().position(|&c| c == b'=') {
            let (k, v) = line.split_at(i);
            let k = k.trim_ascii();
            let v = v[1..].trim_ascii();

            if k == name.as_bytes() {
                let v = str::from_utf8(v)?;
                return Ok(Secret(v.to_string()))
            }
        }
    }

    Err(anyhow!("Key {name} not found in {file}"))
}
