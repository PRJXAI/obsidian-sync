#![forbid(unsafe_code)]
use std::{env, fs::OpenOptions, io::Write, path::Path};
fn main() {
    let executable = env::current_exe().unwrap();
    let root = executable.parent().unwrap();
    let args = env::args().collect::<Vec<_>>();
    let program = Path::new(&args[0]).file_name().unwrap().to_str().unwrap();
    assert_eq!(
        env::var("KUBECONFIG").unwrap_or_default(),
        root.join("kubeconfig").to_str().unwrap_or_default()
    );
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("calls"))
            .unwrap(),
        "{program} {:?}",
        &args[1..]
    )
    .unwrap();
    if program == "k3d" && root.join("delete-fails").exists() {
        std::process::exit(1);
    }
    if program == "docker" && args.iter().any(|v| v == "--filter") && root.join("residual").exists()
    {
        println!("synthetic-residual");
    }
}
