//! Compiled inside rules for the scanner's unit tests; no product interface is added.
use super::{Matcher, Rule, Target, RULES};
use serde_json::Value;

use super::fixture_body::Body;

fn target_key(target: &Target) -> String {
    match target {
        Target::Discovery => "discovery".into(),
        Target::Dir(p) => format!("dir:{p}"),
        Target::File(p) => format!("file:{p}"),
        Target::Each(p, name) => format!("each:{p}|{name}"),
        Target::Name(p) => format!("name:{p}"),
        Target::Profiles(p) => format!("profiles:{p}"),
        Target::Extension(id, _) => format!("extension:{id}"),
        Target::Present(p, _) => format!("present:{p}"),
        Target::Tree(p) => format!("tree:{p}"),
        Target::Repo(p) => format!("repo:{p}"),
    }
}

fn names_path(target: &Target, path: &str) -> bool {
    use std::path::Path;
    let browser_path = |suffix: &str| {
        super::browser::CHROMIUM.iter().any(|browser| {
            path.strip_prefix(&format!("{browser}/"))
                .is_some_and(|rest| {
                    rest == suffix || rest.split_once('/').is_some_and(|(_, rest)| rest == suffix)
                })
        })
    };
    match target {
        Target::Discovery => true,
        Target::File(p) | Target::Present(p, _) => path == *p,
        Target::Dir(p) => Path::new(path).parent() == Some(Path::new(p)),
        Target::Each(p, file) => {
            Path::new(path).file_name().is_some_and(|n| n == *file)
                && Path::new(path).parent().and_then(Path::parent) == Some(Path::new(p))
        }
        Target::Name(_) => Path::new(path).file_name().is_some_and(|n| target.names(n)),
        Target::Tree(p) => path.starts_with(&format!("{p}/")),
        Target::Repo(file) => path.ends_with(&format!("/.git/{file}")),
        Target::Profiles(file) => browser_path(file),
        Target::Extension(id, _) => browser_path(&format!("Local Extension Settings/{id}")),
    }
}

fn matches_body(rule: &Rule, body: &Body) -> bool {
    if matches!(rule.matcher, Matcher::Present) {
        return true;
    }
    let bytes = body.bytes().expect("content rule needs a file");
    let head = &bytes[..bytes.len().min(4096)];
    match rule.matcher {
        Matcher::Head(test) => test(head),
        Matcher::Whole { candidate, test } => {
            candidate(head) && test(&bytes).is_ok_and(|hits| !hits.is_empty())
        }
        Matcher::Stream(test) => test(&bytes, 1).is_ok_and(|hits| !hits.is_empty()),
        Matcher::Present => unreachable!(),
    }
}

fn coverage(cases: &[Value], rules: &[Rule]) -> Result<(), String> {
    let mut covered = vec![false; rules.len()];
    for case in cases {
        let matching: Vec<_> = rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                case["rule"] == rule.id
                    && case["kind"] == rule.kind
                    && case["severity"] == rule.severity
                    && rule.targets.iter().any(|t| case["target"] == target_key(t))
            })
            .collect();
        if matching.len() != 1 {
            return Err(format!(
                "case {} must identify exactly one registered implementation",
                case["name"]
            ));
        }
        let (index, rule) = matching[0];
        let path = case["path"].as_str().ok_or("missing fixture path")?;
        if !rule
            .targets
            .iter()
            .any(|t| case["target"] == target_key(t) && names_path(t, path))
        {
            return Err(format!(
                "case {} is not at its declared target",
                case["name"]
            ));
        }
        let positive: Body = serde_json::from_value(case["positive"].clone())
            .map_err(|_| "invalid positive recipe")?;
        if !matches_body(rule, &positive) {
            return Err(format!(
                "case {} does not exercise its declared matcher",
                case["name"]
            ));
        }
        let negative: Body = serde_json::from_value(case["negative"].clone())
            .map_err(|_| "invalid negative recipe")?;
        let negative_path = case["negative_path"].as_str().unwrap_or(path);
        if names_path(
            rule.targets
                .iter()
                .find(|t| case["target"] == target_key(t))
                .unwrap(),
            negative_path,
        ) && matches_body(rule, &negative)
        {
            return Err(format!(
                "case {} has a matching negative control",
                case["name"]
            ));
        }
        covered[index] = true;
    }
    for (rule, covered) in rules.iter().zip(covered) {
        if !covered {
            return Err(format!(
                "{} ({}, {}) has no detection case",
                rule.id, rule.kind, rule.severity
            ));
        }
    }
    Ok(())
}

#[test]
fn every_registered_implementation_has_a_detection_case() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("../detection-corpus.json")).unwrap();
    assert_eq!(coverage(&cases, RULES), Ok(()));
    // A removed case, an obsolete case, and an ambiguous implementation all fail.
    let missing: Vec<_> = cases
        .iter()
        .filter(|case| case["rule"] != cases[0]["rule"])
        .cloned()
        .collect();
    assert!(
        coverage(&missing, RULES).is_err(),
        "missing implementation escaped the registry check"
    );
    let mut extra_case = cases.clone();
    extra_case.push(cases[0].clone());
    assert_eq!(
        coverage(&extra_case, RULES),
        Ok(()),
        "several cases may cover an implementation"
    );
    assert!(coverage(&cases, &RULES[1..]).is_err());
    let duplicate = [
        super::password_export::PASSWORD_EXPORT,
        super::password_export::PASSWORD_EXPORT,
    ];
    assert!(coverage(&cases[..1], &duplicate).is_err());
    let mut mislabeled = cases.clone();
    let known = mislabeled.iter_mut().find(|c| c["name"] == "aws").unwrap();
    known["path"] = "Downloads/ordinary".into();
    assert!(coverage(&mislabeled, RULES).is_err());
}
