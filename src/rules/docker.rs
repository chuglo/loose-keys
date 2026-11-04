//! Inline registry auth in Docker's user config.

use super::*;

pub const DOCKER_AUTH: Rule = Rule {
    id: "dev.docker.inline-auth",
    category: "developer-cloud",
    kind: "review",
    severity: "medium",
    title: "Docker registry password or token in the config file",
    explanation: "This file has registry sign-in data stored without encryption. Loose Keys did not check whether it still works.",
    reason: Some("Docker on macOS can keep this in the Keychain instead."),
    next_step: Some("Move the sign-in to the Keychain. Removing it from the file does not revoke it; change it at the registry."),
    advice: Advice {
        steps: &[
            "Sign out of each registry listed in the file, which removes its entry: docker logout <registry>",
            "Set \"credsStore\": \"osxkeychain\" in ~/.docker/config.json. Docker Desktop does this by default.",
            "Sign in again with 'docker login'. Use a personal access token, not your account password.",
            "At the registry, revoke the old token or change the password that was stored here.",
        ],
        link: None,
    },
    // Podman and Skopeo use the same format.
    targets: &[
        Target::File(".docker/config.json"),
        Target::File(".config/containers/auth.json"),
        Target::File("Library/Preferences/helm/registry/config.json"),
    ],
    matcher: Matcher::Whole {
        candidate: any,
        test: docker_hits,
    },
    samples: &[
        (br#"{"auths":{"registry":{"auth":"c3ludGhldGlj"}}}"#, true),
        (br#"{"auths":{"registry":{"identitytoken":"synthetic-only-value"}}}"#, true),
        (br#"{"auths":{"registry":{"registrytoken":"synthetic-only-value"}}}"#, true),
        (br#"{"auths":{"registry":{"auth":"${DOCKER_AUTH}"}}}"#, false),
        (br#"{"auths":{"registry":{"identitytoken":"${IDENTITY_TOKEN}","registrytoken":""}}}"#, false),
        (br#"{"credsStore":"osxkeychain","auths":{"registry":{}}}"#, false),
    ],
};

fn docker_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, |v| {
        v["auths"].as_object().is_some_and(|auths| {
            auths
                .values()
                .any(|auth| credentials(auth).next().is_some())
        })
    })
}

/// Docker stores token fields verbatim, alongside base64 username/password auth.
pub(super) fn credentials(auth: &serde_json::Value) -> impl Iterator<Item = (&'static str, &str)> {
    ["auth", "identitytoken", "registrytoken"]
        .into_iter()
        .filter_map(move |field| {
            let value = auth[field].as_str()?;
            let literal = if field == "auth" {
                inline_literal(value)
            } else {
                verbatim_literal(value)
            };
            literal.then_some((field, value))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tokens_are_reported_without_base64_auth() {
        let counts = ["identitytoken", "registrytoken"].map(|field| {
            let config = json!({"auths": {"registry.invalid": {
                field: "synthetic-only-value"
            }}});
            docker_hits(config.to_string().as_bytes()).unwrap().len()
        });
        assert_eq!(counts, [1, 1]);
    }

    #[test]
    fn token_rotation_changes_material_even_beside_auth() {
        let changed = ["identitytoken", "registrytoken"].map(|field| {
            let config = |value| {
                json!({"auths": {"registry.invalid": {
                    "auth": "c3ludGhldGlj", field: value
                }}})
                .to_string()
            };
            material(DOCKER_AUTH.id, config("synthetic-first").as_bytes())
                != material(DOCKER_AUTH.id, config("synthetic-second").as_bytes())
        });
        assert_eq!(changed, [true, true]);
    }

    #[test]
    fn token_fields_require_literal_strings_in_registry_entries() {
        for field in ["identitytoken", "registrytoken"] {
            for value in [
                json!(""),
                json!(" "),
                json!("${FIXTURE_TOKEN}"),
                json!("<token>"),
                json!("*****"),
                json!("env:FIXTURE_TOKEN"),
                json!("file:fixture"),
                json!("keychain:fixture"),
                json!(null),
                json!(true),
                json!(42),
                json!(["synthetic-only-value"]),
                json!({"value": "synthetic-only-value"}),
            ] {
                let config = json!({"auths": {"registry.invalid": {field: value}}});
                assert!(docker_hits(config.to_string().as_bytes())
                    .unwrap()
                    .is_empty());
                assert!(material(DOCKER_AUTH.id, config.to_string().as_bytes()) == b"[]");
            }
            // JSON does not expand shell characters inside a token.
            for value in [
                "synthetic$only-value",
                "!synthetic-only-value",
                "&synthetic-only-value",
            ] {
                let config = json!({"auths": {"registry.invalid": {field: value}}});
                assert_eq!(docker_hits(config.to_string().as_bytes()).unwrap().len(), 1);
            }
            let outside = json!({field: "synthetic-only-value", "auths": {}});
            assert!(docker_hits(outside.to_string().as_bytes())
                .unwrap()
                .is_empty());
        }
        let wrong_shape = json!({"auths": [{"identitytoken": "synthetic-only-value"}]});
        assert!(docker_hits(wrong_shape.to_string().as_bytes())
            .unwrap()
            .is_empty());
        assert!(docker_hits(b"{\"auths\":").is_err());
    }

    #[test]
    fn mixed_credentials_still_produce_one_finding_per_file() {
        let config = json!({"credsStore": "osxkeychain", "auths": {
            "first.invalid": {"auth": "c3ludGhldGlj", "identitytoken": "synthetic-only-value"},
            "second.invalid": {"registrytoken": "synthetic-second-value"}
        }});
        let hits = docker_hits(config.to_string().as_bytes()).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].subject.is_none());
        assert!(hits[0].line.is_none());
    }

    #[test]
    fn auth_only_material_keeps_its_legacy_representation() {
        let config = json!({"auths": {
            "second.invalid": {"auth": "synthetic-second-value", "identitytoken": "${TOKEN}"},
            "first.invalid": {"auth": "c3ludGhldGlj"}
        }});
        let legacy = serde_json::to_vec(&[
            ["first.invalid", "c3ludGhldGlj"],
            ["second.invalid", "synthetic-second-value"],
        ])
        .unwrap();
        assert!(material(DOCKER_AUTH.id, config.to_string().as_bytes()) == legacy);
    }

    #[test]
    fn token_material_preserves_field_and_registry_identity() {
        let config = |registry: &str, field: &str| {
            json!({"auths": {registry: {field: "synthetic-only-value"}}}).to_string()
        };
        let original = material(
            DOCKER_AUTH.id,
            config("first.invalid", "identitytoken").as_bytes(),
        );
        for (registry, field) in [
            ("first.invalid", "registrytoken"),
            ("first.invalid", "auth"),
            ("second.invalid", "identitytoken"),
        ] {
            assert!(original != material(DOCKER_AUTH.id, config(registry, field).as_bytes()));
        }
    }
}
