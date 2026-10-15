//! Standards-based Draft 2020-12 validation, with independent privacy checks.
use super::*;

const SCHEMA: &str = include_str!("../schema/report-1.schema.json");
const FORBIDDEN: &[&str] = &[
    "secret",
    "match",
    "raw",
    "redacted",
    "fingerprint",
    "hash",
    "value",
    "password",
    "token",
];

pub(crate) fn validate(raw: &[u8], manifest: Option<&Value>) -> Result<Vec<String>> {
    validate_with_schema(raw, manifest, SCHEMA)
}
fn validate_with_schema(raw: &[u8], manifest: Option<&Value>, schema: &str) -> Result<Vec<String>> {
    let report: Value = serde_json::from_slice(raw).map_err(|_| "cannot decode report JSON")?;
    let schema: Value = serde_json::from_str(schema).map_err(|_| "cannot decode report schema")?;
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .map_err(|_| "cannot compile report schema")?;
    // Never print validator errors: they may embed an untrusted report value.
    let mut errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|e| format!("schema violation at {}", e.instance_path))
        .collect();
    if !raw.is_ascii() {
        errors.push("not ASCII-only (non-ASCII must be escaped)".into());
    }
    forbidden_keys(&report, &mut errors);
    if let Some(manifest) = manifest {
        let secrets = manifest["forbidden"]["secrets"]
            .as_array()
            .ok_or("missing manifest secrets")?;
        if secrets
            .iter()
            .filter_map(Value::as_str)
            .any(|s| contains(raw, s.as_bytes()))
        {
            errors.push("contains a fixture secret".into());
        }
    }
    Ok(errors)
}
fn forbidden_keys(value: &Value, errors: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if FORBIDDEN.contains(&key.to_lowercase().as_str()) {
                    errors.push("forbidden secret-shaped key".into());
                }
                forbidden_keys(value, errors);
            }
        }
        Value::Array(items) => {
            for item in items {
                forbidden_keys(item, errors);
            }
        }
        _ => {}
    }
}
pub(crate) fn good_report() -> Value {
    json!({"schema":"loose-keys/report/1","tool_version":"0.0.0-selftest","generated_at":"2026-01-01T00:00:00Z","status":"complete","context":"user","findings":[{"rule":"export.browser-csv","category":"password-export","kind":"review","title":"Password export","explanation":"Synthetic reference finding","reason":"Unencrypted export","path":"~/Downloads/export.csv"}],"not_checked":[]})
}
pub(crate) fn self_tests() -> Result<()> {
    let good = good_report();
    let raw = serde_json::to_vec(&good).map_err(|_| "encode report")?;
    if !validate(&raw, None)?.is_empty() {
        return Err("validator rejected known-good report".into());
    }
    let mut mutations = vec![];
    let mut report = good.clone();
    report["findings"][0]["secret"] = json!("x");
    mutations.push(report);
    let mut report = good.clone();
    report["findings"][0]
        .as_object_mut()
        .ok_or("bad base")?
        .remove("reason");
    mutations.push(report);
    let mut report = good.clone();
    report["not_checked"] = json!([{"path":"~/Library/Keychains","reason":"permission-denied"}]);
    mutations.push(report);
    let mut report = good.clone();
    report["findings"][0]["path"] = json!("Users/alice/.aws/credentials");
    mutations.push(report);
    let mut report = good.clone();
    report["findings"][0]["path"] = json!("~/unicode\u{202e}");
    mutations.push(report);
    for (i, report) in mutations.iter().enumerate() {
        let raw = serde_json::to_vec(report).map_err(|_| "encode mutation")?;
        if validate(&raw, None)?.is_empty() {
            return Err(format!("validator accepted mutation {i}"));
        }
    }
    if validate_with_schema(&raw, None, "{\"type\":17}").is_ok() {
        return Err("invalid/unavailable schema did not fail closed".into());
    }
    // Exercise bounds, enums, required fields, conditionals and local references.
    for (field, value) in [
        ("line", json!(0)),
        ("steps", json!([])),
        ("link", json!("http://example.invalid")),
        ("token_type", json!("1bad")),
        ("category", json!("unknown")),
    ] {
        let mut report = good.clone();
        report["findings"][0][field] = value;
        if validate(
            &serde_json::to_vec(&report).map_err(|_| "encode mutation")?,
            None,
        )?
        .is_empty()
        {
            return Err(format!("validator accepted invalid {field}"));
        }
    }
    Ok(())
}
