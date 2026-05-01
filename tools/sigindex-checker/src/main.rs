use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Deserialize)]
struct SignatureIndex {
    schema_version: u32,
    files: Vec<SignatureFile>,
}

#[derive(Deserialize)]
struct SignatureFile {
    name: String,
    sha256: String,
    size: u64,
}

fn usage(program: &str) {
    eprintln!("usage: {program} [signature-dir]");
}

fn signature_dir_from_args() -> Result<PathBuf, String> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "sigindex-checker".to_string());
    let first = args.next();

    if matches!(first.as_deref(), Some("-h" | "--help")) {
        usage(&program);
        std::process::exit(0);
    }

    if args.next().is_some() {
        usage(&program);
        return Err("too many arguments".to_string());
    }

    Ok(first
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("signatures")))
}

fn read_index(directory: &Path) -> Result<SignatureIndex, String> {
    let index_path = directory.join("index.json");
    let text = fs::read_to_string(&index_path)
        .map_err(|error| format!("{}: {error}", index_path.display()))?;

    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", index_path.display()))
}

fn is_safe_file_name(name: &str) -> bool {
    !name.is_empty() && !name.contains("..") && !name.contains('/') && !name.contains('\\')
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn check_file(directory: &Path, file: &SignatureFile) -> Result<(), String> {
    if !is_safe_file_name(&file.name) {
        return Err(format!("{}: unsafe file name", file.name));
    }

    let path = directory.join(&file.name);
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let actual_size = bytes.len() as u64;
    if actual_size != file.size {
        return Err(format!(
            "{}: size mismatch, expected {}, got {}",
            file.name, file.size, actual_size
        ));
    }

    let expected_hash = file.sha256.to_ascii_lowercase();
    let actual_hash = sha256_hex(&bytes);
    if actual_hash != expected_hash {
        return Err(format!(
            "{}: sha256 mismatch, expected {}, got {}",
            file.name, expected_hash, actual_hash
        ));
    }

    Ok(())
}

fn run() -> Result<(), Vec<String>> {
    let directory = signature_dir_from_args().map_err(|error| vec![error])?;
    let index = read_index(&directory).map_err(|error| vec![error])?;
    let mut errors = Vec::new();

    if index.schema_version != 1 {
        errors.push(format!(
            "unsupported schema_version {}",
            index.schema_version
        ));
    }

    if index.files.is_empty() {
        errors.push("index has no files".to_string());
    }

    for file in &index.files {
        if let Err(error) = check_file(&directory, file) {
            errors.push(error);
        }
    }

    if errors.is_empty() {
        println!(
            "checked {} file(s) in {}",
            index.files.len(),
            directory.display()
        );
        println!("ok");
        Ok(())
    } else {
        Err(errors)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(errors) => {
            for error in errors {
                eprintln!("{error}");
            }
            ExitCode::FAILURE
        }
    }
}
