//! Inline registry auth in Docker's user config.

use super::*;

pub const DOCKER_AUTH: Rule = Rule {
    id: "dev.docker.inline-auth",
    category: "developer-cloud",
    kind: "review",
    severity: "medium",
    title: "Docker registry password in the config file",
    explanation: "This file has a saved registry sign-in. Docker stores it in base64, which anyone can decode. Loose Keys did not check whether it still works.",
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
        (br#"{"auths":{"registry":{"auth":"${DOCKER_AUTH}"}}}"#, false),
        (br#"{"credsStore":"osxkeychain","auths":{"registry":{}}}"#, false),
    ],
};

fn docker_hits(bytes: &[u8]) -> Hits {
    json_hits(bytes, |v| {
        v["auths"].as_object().is_some_and(|auths| {
            auths
                .values()
                .any(|a| a["auth"].as_str().is_some_and(inline_literal))
        })
    })
}
