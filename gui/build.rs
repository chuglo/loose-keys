fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let object = out.join("notifications.o");
    let target = std::env::var("TARGET").unwrap();
    let arch = if target.starts_with("aarch64") {
        "arm64"
    } else {
        "x86_64"
    };
    // The app's minimum macOS, which .cargo/config.toml sets for every
    // Cargo build. Cargo hides clang's warnings, so an API newer than it
    // without an @available check fails the build instead.
    let minimum = std::env::var("MACOSX_DEPLOYMENT_TARGET")
        .expect("MACOSX_DEPLOYMENT_TARGET is set in .cargo/config.toml");
    assert!(std::process::Command::new("clang")
        .args([
            "-fobjc-arc",
            "-fblocks",
            &format!("-mmacosx-version-min={minimum}"),
            "-Werror=unguarded-availability",
            "-arch",
            arch,
            "-c",
            "src/notifications.m",
            "-o"
        ])
        .arg(&object)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("ar")
        .arg("crs")
        .arg(out.join("libnotifications.a"))
        .arg(object)
        .status()
        .unwrap()
        .success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=notifications");
    // Rust suppresses Clang's default libraries. @available guards need
    // the installed compiler's native availability runtime explicitly.
    let runtime = std::process::Command::new("clang")
        .arg("-print-file-name=libclang_rt.osx.a")
        .output()
        .unwrap();
    assert!(runtime.status.success());
    let runtime = std::path::PathBuf::from(String::from_utf8(runtime.stdout).unwrap().trim());
    assert!(
        runtime.is_file(),
        "Clang availability runtime is unavailable"
    );
    println!(
        "cargo:rustc-link-search=native={}",
        runtime.parent().unwrap().display()
    );
    println!("cargo:rustc-link-lib=static=clang_rt.osx");
    println!("cargo:rustc-link-lib=framework=UserNotifications");
    println!("cargo:rustc-link-lib=framework=AppKit");
    println!("cargo:rustc-link-lib=framework=ServiceManagement");
    println!("cargo:rustc-link-lib=framework=CoreServices");
    println!("cargo:rerun-if-changed=src/notifications.m");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
}
