use loose_keys::{fsutil, report, rules, scan};

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: loose-keys scan [--select DIR ...] [--exclude DIR ...] [--limits]
                               [--export PATH | --feedback PATH [--device-id NAME]]
                               [--fail-on-open LEVEL]
       loose-keys --list-rules

Looks through your home folder for passwords, keys and tokens that
password-stealing malware could take. That includes password exports and notes,
private keys, cloud and developer tokens, secrets in AI tools and their session
records, passwords and cards saved in browsers, and crypto wallets and recovery
phrases. Each finding says what to do about it.
Loose Keys works offline, changes nothing and never shows secret values.

  --export PATH   write the JSON report to PATH (new file, owner-only)
  --export -      write the JSON report to stdout instead of the summary
  --feedback PATH write counts only to PATH (new file, owner-only; no paths or values)
  --feedback -    write counts only to stdout instead of the summary
  --device-id NAME
                  with --feedback: also record this name for the Mac (such as its
                  serial number) and the time of the scan, for device management.
                  Without it, the counts include neither.
  --select DIR    also scan this folder or mounted drive and everything in it (repeatable)
  --exclude DIR   skip this folder (repeatable). The report always lists it, and
                  known sign-in files such as ~/.aws/credentials are still checked.
  --limits        also print what this scan cannot detect
  --fail-on-open LEVEL
                  exit with 3 if anything worth reviewing is at this risk level or
                  above (high, medium or low). For device-management checks.

Choose --export or --feedback, not both. A full report contains file paths,
and a counts file shows which kinds of credentials you have. Check either one
before you share it.

Exit codes: 0 scan complete, 1 scan partial (something could not be checked), 2 error.
These never depend on what was found, unless --fail-on-open is given: then 3 means
findings at or above that level are open. 2 takes precedence over 3, and 3 over 1.";

fn main() -> ExitCode {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--version" {
        println!("loose-keys {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.len() == 1 && args[0] == "--list-rules" {
        print!("{}", rules::rule_list());
        return ExitCode::SUCCESS;
    }
    if args.is_empty()
        || (args.len() == 1 && (args[0] == "--help" || args[0] == "-h"))
        || (args.len() == 2 && args[0] == "scan" && (args[1] == "--help" || args[1] == "-h"))
    {
        println!("{}", USAGE);
        return ExitCode::SUCCESS;
    }
    let limits = args.iter().any(|a| a == "--limits");
    args.retain(|a| a != "--limits");
    if args.first().is_none_or(|a| a != "scan") || args.len() % 2 == 0 {
        eprintln!("{}", USAGE);
        return ExitCode::from(2);
    }
    let mut export: Option<PathBuf> = None;
    let mut feedback = false;
    let mut device: Option<String> = None;
    let mut selected = Vec::new();
    let mut excluded = Vec::new();
    let mut fail_on: Option<usize> = None;
    let home = match scan::home() {
        Ok(home) => home,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    for pair in args[1..].as_chunks::<2>().0 {
        match pair[0].to_str() {
            Some("--fail-on-open") if fail_on.is_none() => {
                fail_on = LEVELS.iter().position(|level| pair[1] == *level);
                if fail_on.is_none() {
                    eprintln!("error: --fail-on-open takes high, medium or low");
                    return ExitCode::from(2);
                }
            }
            Some("--exclude") if !pair[1].is_empty() && excluded.len() < 32 => {
                match scan::skipped_folder(&pair[1], &home) {
                    Ok(path) if !excluded.contains(&path) => excluded.push(path),
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            Some("--export" | "--feedback") if export.is_none() && !pair[1].is_empty() => {
                feedback = pair[0] == "--feedback";
                export = Some(PathBuf::from(&pair[1]));
            }
            Some("--device-id") if device.is_none() => {
                // What an inventory calls a Mac: a serial number, an asset tag, a host name.
                let name = pair[1].to_str().filter(|name| {
                    (1..=64).contains(&name.len())
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                });
                let Some(name) = name else {
                    eprintln!(
                        "error: --device-id takes 1 to 64 letters, digits, dots, dashes, colons or underscores"
                    );
                    return ExitCode::from(2);
                };
                device = Some(name.to_owned());
            }
            Some("--select") if !pair[1].is_empty() => match scan::selected_root(&pair[1]) {
                Ok(path) if !selected.contains(&path) => selected.push(path),
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            },
            _ => {
                eprintln!("{}", USAGE);
                return ExitCode::from(2);
            }
        }
    }
    if device.is_some() && !feedback {
        eprintln!("error: --device-id goes with --feedback");
        return ExitCode::from(2);
    }

    let r = scan::Scan::report_excluding(&home, &selected, &excluded);

    let json = export.as_ref().map(|_| match (feedback, &device) {
        (true, Some(device)) => report::to_device_counts_json(&r, device),
        (true, None) => report::to_feedback_json(&r),
        (false, _) => report::to_ascii_json(&r),
    });
    match export.as_deref() {
        Some(path) if path == Path::new("-") => println!("{}", json.as_ref().unwrap()),
        Some(path) => {
            if let Err(e) = fsutil::write_export(path, json.as_ref().unwrap(), scan::is_root()) {
                eprintln!(
                    "error: not exporting to \"{}\": {}",
                    report::escape(&path.to_string_lossy()),
                    e
                );
                return ExitCode::from(2);
            }
            print!("{}", report::to_text(&r, limits));
        }
        None => print!("{}", report::to_text(&r, limits)),
    }
    // Open means worth reviewing. This stateless command knows nothing of
    // what a person has set aside in the app.
    let open = fail_on.is_some_and(|level| {
        r.findings.iter().any(|f| {
            f.kind == "review" && LEVELS.iter().position(|l| *l == f.severity) <= Some(level)
        })
    });
    ExitCode::from(match (open, r.status) {
        (true, _) => 3,
        (false, "complete") => 0,
        (false, _) => 1,
    })
}

/// Risk levels, most serious first.
const LEVELS: [&str; 3] = ["high", "medium", "low"];
