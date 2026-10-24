#![forbid(unsafe_code)]

pub mod clients;
pub mod deployment;
pub mod docs;
pub mod evidence;
pub mod grype;
pub mod images;
pub mod policy;
pub mod rebuild;
pub mod sbom;
pub mod security;
pub mod supply_sbom;
pub mod util;

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub fn ensure(condition: bool, message: &str) -> Result {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(message).into())
    }
}
pub fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .into()
}
