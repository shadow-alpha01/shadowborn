//! Synthetic lab helper: consume a private fixture file, never print secrets.
use anyhow::{Context, Result};
use shadowborn_core::{bundle, State};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};
fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    anyhow::ensure!(
        args.len() == 2,
        "usage: render_lab FIXTURE_JSON NEW_OUTPUT_DIR"
    );
    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let state: State =
        serde_json::from_slice(&fs::read(input)?).context("invalid synthetic fixture")?;
    let files = bundle(&state)?;
    fs::create_dir(&output)?;
    for (name, data) in files {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output.join(name))?;
        file.write_all(data.as_bytes())?;
    }
    Ok(())
}
