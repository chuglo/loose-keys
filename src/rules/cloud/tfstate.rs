//! Credentials stored in Terraform state.

use super::super::{label, plausible, Hit, Hits, Incomplete};
use serde_json::Value;
use std::collections::HashSet;

const SENSITIVE_NODES: usize = 32_000;

/// Attribute names providers use for secrets they write to state.
const STATE_SECRETS: &[&str] = &[
    "password",
    "master_password",
    "secret",
    "secret_key",
    "ses_smtp_password_v4",
    "client_secret",
    "token",
    "private_key",
    "private_key_pem",
];

/// One hit for each resource, sensitive output and backend that holds a
/// literal secret, named for it.
pub(in crate::rules) fn tfstate_hits(bytes: &[u8]) -> Hits {
    // Terraform leaves an empty file behind in some workflows.
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(vec![]);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| "unreadable")?;
    // By the name as it will be shown: the scan keeps one finding for a
    // name, and one for all the holders whose names cannot be shown.
    let mut out: Vec<Hit> = Vec::new();
    let (held, mut limited) = state_secrets(&v);
    for held in held {
        let subject = label(&held.shown());
        if let Some(hit) = out.iter_mut().find(|hit| hit.subject == subject) {
            // Listed at low risk only if all it holds is short-lived.
            hit.low &= held.low;
        } else if out.len() < 100 {
            out.push(Hit {
                subject,
                low: held.low,
                ..Hit::file()
            });
        } else {
            limited = true;
        }
    }
    if limited {
        Err(Incomplete {
            reason: "scan-limit",
            hits: out,
        })
    } else {
        Ok(out)
    }
}

/// What the app fingerprints for this rule: the secrets, not the rest of a
/// file that every `terraform apply` rewrites. Never export this.
pub(in crate::rules) fn tfstate_material(bytes: &[u8]) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    // Not the credentials that last minutes: each apply fetches new ones,
    // and they are listed, never brought up for review.
    let mut held: Vec<_> = state_secrets(&v)
        .0
        .into_iter()
        .filter(|held| !held.low)
        .map(|held| (held.holder, held.secrets))
        .collect();
    held.sort();
    serde_json::to_vec(&held).ok()
}

/// What holds secrets in a state file: a resource by its type and name, an
/// output, or the backend. Everything is borrowed from the file as parsed,
/// so the work stays in proportion to the file whatever it repeats.
pub(in crate::rules) struct Held<'a> {
    holder: (&'a str, &'a str),
    /// Each attribute that is a literal secret, and its value.
    pub(in crate::rules) secrets: Vec<(&'a str, &'a str)>,
    /// All of it is credentials that last minutes or hours.
    low: bool,
}

impl Held<'_> {
    fn shown(&self) -> String {
        match self.holder {
            ("", name) => name.to_string(),
            (kind, name) => format!("{kind}.{name}"),
        }
    }
}

pub(in crate::rules) fn state_secrets(v: &Value) -> (Vec<Held<'_>>, bool) {
    let mut out = Vec::new();
    let mut limited = false;
    if !v["terraform_version"].is_string() {
        return (out, limited);
    }
    let mut remaining = SENSITIVE_NODES;
    for resource in v["resources"].as_array().into_iter().flatten() {
        let kind = resource["type"].as_str().unwrap_or("");
        let name = resource["name"].as_str().unwrap_or("");
        let instances = resource["instances"].as_array().into_iter().flatten();
        out.extend(resource_secrets(
            kind,
            name,
            instances,
            &mut remaining,
            &mut limited,
        ));
    }
    // Version 3, written before Terraform 0.12: the resources of each module
    // by "type.name", with the attributes under "primary" and those of copies
    // kept from before a replacement under "deposed".
    let modules = v["modules"].as_array().into_iter().flatten();
    for (key, resource) in modules
        .clone()
        .filter_map(|m| m["resources"].as_object())
        .flatten()
    {
        let kind = resource["type"].as_str().unwrap_or("");
        let key = key.strip_prefix("data.").unwrap_or(key);
        let name = key
            .strip_prefix(kind)
            .and_then(|k| k.strip_prefix('.'))
            .unwrap_or(key);
        let deposed = resource["deposed"].as_array().into_iter().flatten();
        let instances = std::iter::once(&resource["primary"]).chain(deposed);
        out.extend(resource_secrets(
            kind,
            name,
            instances,
            &mut remaining,
            &mut limited,
        ));
    }
    let outputs = v["outputs"].as_object().into_iter();
    let outputs = outputs.chain(modules.filter_map(|m| m["outputs"].as_object()));
    for (name, output) in outputs.flatten() {
        if output["sensitive"] != true {
            continue;
        }
        let mut secrets = Vec::new();
        limited |= !sensitive_values(
            &output["value"],
            "value",
            &mut HashSet::new(),
            &mut remaining,
            &mut secrets,
        );
        secrets.sort_unstable();
        secrets.dedup();
        if !secrets.is_empty() {
            out.push(Held {
                holder: ("output", name),
                secrets,
                low: false,
            });
        }
    }
    // The backend settings Terraform copies into .terraform/terraform.tfstate.
    let backend = ["access_key", "secret_key", "password", "token", "sas_token"];
    let secrets: Vec<_> = backend
        .iter()
        .filter_map(|name| Some((*name, stored(&v["backend"]["config"][*name])?)))
        .collect();
    if !secrets.is_empty() {
        out.push(Held {
            holder: ("", "backend"),
            secrets,
            low: false,
        });
    }
    (out, limited)
}

fn stored(v: &Value) -> Option<&str> {
    v.as_str()
        .filter(|s| s.len() >= 8 && !s.starts_with('$') && plausible(s))
}

/// What one resource holds across its instances, if any of it is a secret.
fn resource_secrets<'a>(
    kind: &'a str,
    name: &'a str,
    instances: impl Iterator<Item = &'a Value> + Clone,
    remaining: &mut usize,
    limited: &mut bool,
) -> Option<Held<'a>> {
    // "result" is what was generated: a secret only for a password.
    let generated = (kind == "random_password").then_some("result");
    let mut secrets = Vec::new();
    *limited |= instances.clone().nth(1000).is_some();
    for instance in instances.take(1000) {
        let attributes = &instance["attributes"];
        // What Terraform itself marked sensitive, by the attribute each path
        // starts at. Counted by that name: a helm_release marks one attribute
        // at a path for each of its set_sensitive blocks.
        let mut names: Vec<&str> = Vec::new();
        // The maps and lists already examined, so that many paths marking
        // one large map cost no more than one.
        let mut examined = HashSet::new();
        let paths = instance["sensitive_attributes"].as_array().into_iter();
        for path in paths.flatten() {
            let Some(name) = path.get(0).and_then(|step| step["value"].as_str()) else {
                continue;
            };
            if !names.contains(&name) {
                if names.len() == 100 {
                    *limited = true;
                    break;
                }
                names.push(name);
            }
            let Some(at) = marked_value(attributes, path) else {
                continue;
            };
            if !sensitive_values(at, name, &mut examined, remaining, &mut secrets) {
                *limited = true;
                break;
            }
        }
        let usual = STATE_SECRETS.iter().copied().chain(generated);
        for name in usual {
            if let Some(value) = stored(&attributes[name]) {
                secrets.push((name, value));
            }
        }
    }
    secrets.sort_unstable();
    secrets.dedup();
    (!secrets.is_empty()).then_some(Held {
        holder: (kind, name),
        secrets,
        low: matches!(kind, "aws_eks_cluster_auth" | "aws_ecr_authorization_token"),
    })
}

/// Visit marked strings without allocating a list as wide as a collection.
fn sensitive_values<'a>(
    root: &'a Value,
    name: &'a str,
    examined: &mut HashSet<*const Value>,
    remaining: &mut usize,
    secrets: &mut Vec<(&'a str, &'a str)>,
) -> bool {
    fn children(value: &Value) -> impl Iterator<Item = &Value> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .chain(value.as_object().into_iter().flat_map(|map| map.values()))
    }

    let mut parents = Vec::new();
    let mut next = Some(root);
    loop {
        if let Some(value) = next {
            if examined.insert(std::ptr::from_ref(value)) {
                if *remaining == 0 {
                    return false;
                }
                *remaining -= 1;
                if let Some(secret) = stored(value) {
                    secrets.push((name, secret));
                }
                if value.is_array() || value.is_object() {
                    parents.push(children(value));
                }
            }
        }
        let Some(parent) = parents.last_mut() else {
            return true;
        };
        next = parent.next();
        if next.is_none() {
            parents.pop();
        }
    }
}

/// What a path Terraform marked sensitive leads to in the attributes: a
/// value, or a map or list marked whole, as a kubernetes_secret's "data" is.
/// Each step names an attribute ("get_attr", whose value is the name), or a
/// list position or map key ("index", whose value says which).
fn marked_value<'a>(attributes: &'a Value, path: &Value) -> Option<&'a Value> {
    let mut at = attributes;
    for step in path.as_array()? {
        let key = &step["value"];
        at = match (key, key["type"].as_str()) {
            (Value::String(name), _) => at.get(name.as_str())?,
            (_, Some("number")) => at.get(usize::try_from(key["value"].as_u64()?).ok()?)?,
            (_, Some("string")) => at.get(key["value"].as_str()?)?,
            _ => return None,
        };
    }
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_sensitive_walk_reports_only_values_it_visited_and_says_when_it_stops() {
        for count in [SENSITIVE_NODES - 1, SENSITIVE_NODES] {
            let mut values = vec![Value::Null; count];
            values[0] = json!("synthetic-first-value");
            values[count - 1] = json!("synthetic-last-value");
            let state = json!({"terraform_version": "1.9.0",
                "outputs": {"fixture": {"sensitive": true, "value": values}}});
            let bytes = serde_json::to_vec(&state).unwrap();
            let (held, limited) = state_secrets(&state);
            assert_eq!(limited, count == SENSITIVE_NODES);
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].secrets.len(), if limited { 1 } else { 2 });
            if limited {
                let incomplete = tfstate_hits(&bytes)
                    .err()
                    .expect("the next value exceeds the budget");
                assert_eq!(incomplete.reason, "scan-limit");
                assert_eq!(incomplete.hits.len(), 1);
            } else {
                assert_eq!(tfstate_hits(&bytes).unwrap().len(), 1);
            }
        }
    }

    #[test]
    fn version_3_state_is_searched_as_version_4_is() {
        let attributes =
            |name: &str| json!({"id": "fixture", "attributes": {name: "synthetic-only-value"}});
        let state = json!({"version": 3, "terraform_version": "0.11.14", "modules": [
            {"path": ["root"],
             "outputs": {"db_password": {"sensitive": true, "type": "string", "value": "synthetic-only-value"}},
             "resources": {
                "aws_db_instance.fixture": {"type": "aws_db_instance", "primary": attributes("password")},
                "data.aws_secret.fixture": {"type": "aws_secret", "primary": attributes("secret")},
                // Counted, and with a secret only in a copy kept from before
                // it was replaced.
                "aws_iam_access_key.fixture.0": {"type": "aws_iam_access_key",
                    "primary": attributes("user"), "deposed": [attributes("secret")]},
             }},
            {"path": ["root", "child"], "outputs": {},
             "resources": {"random_password.fixture": {"type": "random_password", "primary": attributes("result")}}},
        ]});
        let hits = tfstate_hits(state.to_string().as_bytes()).unwrap();
        let mut subjects: Vec<_> = hits.iter().filter_map(|h| h.subject.clone()).collect();
        subjects.sort();
        assert_eq!(
            subjects,
            [
                "aws_db_instance.fixture",
                "aws_iam_access_key.fixture.0",
                "aws_secret.fixture",
                "output.db_password",
                "random_password.fixture",
            ]
        );
    }

    #[test]
    fn sensitive_attributes_are_counted_by_name() {
        let state = |paths: Vec<Value>, attributes: Value| {
            json!({"version": 4, "terraform_version": "1.9.0", "resources": [
                {"mode": "managed", "type": "helm_release", "name": "fixture",
                 "instances": [{"attributes": attributes, "sensitive_attributes": paths}]},
            ]})
            .to_string()
        };
        // A helm_release marks each of its set_sensitive blocks: many paths,
        // one name, and nothing left unexamined. Only the last block holds a
        // value, inside the list, under no name a secret usually has.
        for count in [100, 101] {
            let paths = (0..count)
                .map(|n| {
                    json!([{"type": "get_attr", "value": "set_sensitive"},
                           {"type": "index", "value": {"value": n, "type": "number"}},
                           {"type": "get_attr", "value": "value"}])
                })
                .collect();
            let mut blocks = vec![json!({"name": "fixture", "value": ""}); count - 1];
            blocks.push(json!({"name": "fixture", "value": "synthetic-only-value"}));
            let attributes = json!({"set_sensitive": blocks});
            let hits = tfstate_hits(state(paths, attributes).as_bytes());
            assert_eq!(hits.map(|hits| hits.len()).ok(), Some(1), "{count}");
        }
        // Past 100 different names the rest are not examined: what was
        // found stays, with the gap.
        for count in [100, 101] {
            let paths = (0..count)
                .map(|n| json!([{"type": "get_attr", "value": format!("field{n}")}]))
                .collect();
            let attributes = json!({"field0": "synthetic-only-value"});
            let hits = tfstate_hits(state(paths, attributes).as_bytes());
            match hits {
                Ok(hits) => assert_eq!((count, hits.len()), (100, 1)),
                Err(incomplete) => {
                    assert_eq!(count, 101);
                    assert_eq!(incomplete.reason, "scan-limit");
                    assert_eq!(incomplete.hits.len(), 1);
                }
            }
        }
    }

    /// A value Terraform marked sensitive is examined wherever the marked
    /// path leads: a whole map, or one entry of it.
    #[test]
    fn marked_values_inside_maps_are_examined() {
        let state = |paths: Value, data: Value| {
            json!({"version": 4, "terraform_version": "1.9.0", "resources": [
                {"mode": "managed", "type": "kubernetes_secret", "name": "fixture",
                 "instances": [{"attributes": {"data": data, "type": "Opaque"},
                                "sensitive_attributes": paths}]},
            ]})
            .to_string()
        };
        let data = |value: &str| json!({"username": "", "credentials": value});
        let whole = json!([[{"type": "get_attr", "value": "data"}]]);
        let entry = json!([[{"type": "get_attr", "value": "data"},
                            {"type": "index", "value": {"value": "credentials", "type": "string"}}]]);
        for paths in [whole, entry] {
            let found = state(paths.clone(), data("synthetic-only-value"));
            let hits = tfstate_hits(found.as_bytes()).unwrap();
            let subjects: Vec<_> = hits.iter().map(|h| h.subject.as_deref()).collect();
            assert_eq!(subjects, [Some("kubernetes_secret.fixture")]);
            // What the app fingerprints follows the value.
            let other = state(paths.clone(), data("synthetic-second-value"));
            assert_ne!(
                tfstate_material(found.as_bytes()),
                tfstate_material(other.as_bytes())
            );
            assert!(tfstate_hits(state(paths, data("")).as_bytes())
                .unwrap()
                .is_empty());
        }
    }

    /// Many marked paths that lead to one large map examine it once.
    #[test]
    fn a_map_marked_many_times_is_examined_once() {
        let data: serde_json::Map<String, Value> =
            (0..20_000).map(|n| (format!("k{n}"), json!(""))).collect();
        let paths = vec![json!([{"type": "get_attr", "value": "data"}]); 20_000];
        let state = json!({"version": 4, "terraform_version": "1.9.0", "resources": [
            {"mode": "managed", "type": "kubernetes_secret", "name": "fixture",
             "instances": [{"attributes": {"data": data}, "sensitive_attributes": paths}]},
        ]})
        .to_string();
        let started = std::time::Instant::now();
        assert!(tfstate_hits(state.as_bytes()).unwrap().is_empty());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(10),
            "checking {} bytes took {took:?}",
            state.len()
        );
    }
}
