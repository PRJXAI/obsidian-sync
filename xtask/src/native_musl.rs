//! Build-only adapter: a native GNU SDK must still produce native static-musl artifacts.
#![forbid(unsafe_code)]

use std::ffi::OsString;

fn targets(arch: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match arch {
        "aarch64" => Some((
            "aarch64-unknown-linux-musl",
            "aarch64-linux-musl",
            "AARCH64_UNKNOWN_LINUX_MUSL",
        )),
        "x86_64" => Some((
            "x86_64-unknown-linux-musl",
            "x86_64-linux-musl",
            "X86_64_UNKNOWN_LINUX_MUSL",
        )),
        _ => None,
    }
}

fn info_args(args: &[OsString]) -> bool {
    match args {
        [arg] => arg == "--version" || arg == "-vV",
        [option, value] => option == "--print" && value == "target-libdir",
        _ => false,
    }
}

fn rustflags(arch: &str) -> Option<&'static str> {
    match arch {
        "aarch64" => Some(
            "-Ctarget-feature=+crt-static -Clinker-flavor=ld.lld -Clink-arg=--fix-cortex-a53-843419",
        ),
        "x86_64" => Some("-Ctarget-feature=+crt-static -Clinker-flavor=ld.lld"),
        _ => None,
    }
}

// cc-rs can repeat a Clang target. Normalize only the exact native musl
// spellings; never let a later argument silently redirect the fixed target.
fn compiler_args(
    args: Vec<OsString>,
    rust: &str,
    zig: &str,
) -> Result<Vec<OsString>, &'static str> {
    // Retain Zig/Clang's undefined-behavior checks as traps, so a Rust-linked
    // static executable does not depend on an unlinked UBSan recovery runtime.
    let mut output = vec![
        OsString::from("-target"),
        zig.into(),
        "-fsanitize-trap=undefined".into(),
    ];
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy();
        let target = if matches!(text.as_ref(), "-target" | "--target") {
            Some(args.next().ok_or("missing compiler target")?)
        } else {
            text.strip_prefix("--target=")
                .or_else(|| text.strip_prefix("-target="))
                .map(OsString::from)
        };
        if let Some(target) = target {
            if target != rust && target != zig {
                return Err("only the native musl compiler target is allowed");
            }
        } else {
            output.push(arg);
        }
    }
    Ok(output)
}

#[cfg(not(test))]
fn main() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    let Some((rust, zig, key)) = targets(std::env::consts::ARCH) else {
        eprintln!("unsupported native musl architecture");
        std::process::exit(1);
    };
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    let name = std::path::Path::new(&program)
        .file_name()
        .and_then(|v| v.to_str());
    let mut command = match name {
        Some("native-musl-install-target") => {
            if args.next().is_some() {
                eprintln!("native target installation accepts no overrides");
                std::process::exit(1);
            }
            let mut command = Command::new("rustup");
            command.args(["target", "add", "--toolchain", "1.99.1", rust]);
            command
        }
        Some("native-musl-info") => {
            let args = args.collect::<Vec<_>>();
            if !info_args(&args) {
                eprintln!("invalid native musl identity request");
                std::process::exit(1);
            }
            let mut command = Command::new(format!(
                "/usr/local/rustup/toolchains/1.99.1-{}-unknown-linux-gnu/bin/rustc",
                std::env::consts::ARCH
            ));
            command.args(["--target", rust]).args(args);
            command
        }
        Some("native-musl-cargo") => {
            let mut command = Command::new("rustup");
            command.args(["run", "1.99.1", "cargo"]);
            let cc = "/usr/local/bin/native-musl-cc";
            let cxx = "/usr/local/bin/native-musl-cxx";
            // Distribution rustc/cargo binaries are not rustup proxies. Make
            // every Cargo child use the installed, fixed upstream toolchain.
            let bin = std::path::PathBuf::from(format!(
                "/usr/local/rustup/toolchains/1.99.1-{}-unknown-linux-gnu/bin",
                std::env::consts::ARCH
            ));
            let mut paths = vec![bin.clone()];
            paths.extend(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            ));
            let Ok(path) = std::env::join_paths(paths) else {
                eprintln!("invalid native SDK executable path");
                std::process::exit(1);
            };
            command
                .env("PATH", path)
                .env("RUSTC", bin.join("rustc"))
                .env("RUSTDOC", bin.join("rustdoc"));
            // Rust's own self-contained musl linker keeps architecture errata
            // mitigations (including Cortex-A53 843419), not Zig's ELF linker.
            let linker = bin.parent().unwrap().join(format!(
                "lib/rustlib/{}-unknown-linux-gnu/bin/rust-lld",
                std::env::consts::ARCH
            ));
            command
                .env("CARGO_BUILD_TARGET", rust)
                .env(format!("CARGO_TARGET_{key}_LINKER"), linker)
                .env(format!("CC_{}", rust.replace('-', "_")), cc)
                .env(format!("CXX_{}", rust.replace('-', "_")), cxx)
                .env("RUSTFLAGS", rustflags(std::env::consts::ARCH).unwrap())
                .args(args);
            command
        }
        Some("native-musl-cc" | "native-musl-cxx") => {
            let mut command = Command::new("/usr/bin/zig");
            command.arg(if name == Some("native-musl-cxx") {
                "c++"
            } else {
                "cc"
            });
            let Ok(args) = compiler_args(args.collect(), rust, zig) else {
                eprintln!("invalid native musl compiler arguments");
                std::process::exit(1);
            };
            command.args(args);
            command
        }
        _ => {
            eprintln!("invalid native musl adapter name");
            std::process::exit(1);
        }
    };
    let _ = command.exec();
    eprintln!("native musl adapter could not execute its fixed tool");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_queries_cannot_compile_or_override_the_native_target() {
        for args in [
            vec!["--version"],
            vec!["-vV"],
            vec!["--print", "target-libdir"],
        ] {
            assert!(info_args(
                &args.into_iter().map(OsString::from).collect::<Vec<_>>()
            ));
        }
        for args in [
            vec![],
            vec!["file.rs"],
            vec!["--target=x86_64-unknown-linux-gnu"],
            vec!["--print", "sysroot"],
            vec!["--version", "file.rs"],
        ] {
            assert!(!info_args(
                &args.into_iter().map(OsString::from).collect::<Vec<_>>()
            ));
        }
    }
    #[test]
    fn native_targets_are_explicit_and_never_gnu() {
        for arch in ["aarch64", "x86_64"] {
            let (rust, zig, key) = targets(arch).unwrap();
            assert!(rust.ends_with("-unknown-linux-musl"));
            assert!(zig.ends_with("-linux-musl"));
            assert!(key.ends_with("_LINUX_MUSL"));
        }
        assert!(targets("riscv64").is_none());
        assert!(
            rustflags("aarch64")
                .unwrap()
                .contains("--fix-cortex-a53-843419")
        );
        assert!(!rustflags("x86_64").unwrap().contains("cortex"));
        assert!(rustflags("riscv64").is_none());
    }
    #[test]
    fn compiler_targets_cannot_override_native_musl() {
        let (rust, zig, _) = targets("aarch64").unwrap();
        let args = [
            "-c",
            "file.c",
            "--target=aarch64-unknown-linux-musl",
            "-target",
            "aarch64-linux-musl",
        ]
        .map(OsString::from)
        .to_vec();
        assert_eq!(
            compiler_args(args, rust, zig).unwrap(),
            ["-target", zig, "-fsanitize-trap=undefined", "-c", "file.c"].map(OsString::from)
        );
        for args in [
            vec!["--target=x86_64-linux-musl"],
            vec!["-target", "aarch64-linux-gnu"],
            vec!["-target"],
        ] {
            assert!(
                compiler_args(args.into_iter().map(OsString::from).collect(), rust, zig).is_err()
            );
        }
    }
}
