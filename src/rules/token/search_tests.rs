use super::*;

use crate::encoded_image_fixture as fixture;

fn key() -> String {
    ["LTAI", "0123456789abcdefghij"].concat()
}

#[test]
fn image_signatures_skip_only_the_payload() {
    // Encoded JPEG, GIF and WebP headers exercise recognition, not full
    // image validation. The PNG fixture is a complete image.
    for header in [
        "iVBORw0KGgoAAAANSUhEUgAA",
        "/9j/4AAQSkZJRgABAQAAAQAB",
        "R0lGODlhAQABAIAAAAAAAAAA",
        "UklGRhIAAABXRUJQVlA4TAEA",
    ] {
        let image = [header, "/", "LTAI", "0123456789abcdefG", "//"].concat();
        let token = key();
        let input =
            format!("{token}\n{{\"data\":\"{image}\"}}\nhttps://fixture.invalid/{token}/notes\n");
        let hits = token_hits(input.as_bytes()).unwrap();
        assert_eq!(hits.len(), 2, "header: {header}");
        assert_eq!(hits[0].line, Some(1));
        assert_eq!(hits[1].line, Some(3));
        for hit in hits {
            assert!(input.as_bytes().get(hit.span.unwrap()) == Some(token.as_bytes()));
        }
    }
}

#[test]
fn image_labels_and_invalid_encodings_do_not_hide_keys() {
    let token = key();
    let mislabeled = format!("{{\"type\":\"image\",\"source\":{{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"{token}\"}}}}");
    assert_eq!(token_hits(mislabeled.as_bytes()).unwrap().len(), 1);
    for suffix in ["A", "=", "====", "=AAA"] {
        let malformed = format!("{}{}\"", fixture::png(false), suffix);
        assert_eq!(token_hits(malformed.as_bytes()).unwrap().len(), 1);
    }
    let false_header = [
        "iVBORw0KGgoAAAANSUhEVgAAAA/",
        "LTAI",
        "0123456789abcdefG",
        "//",
    ]
    .concat();
    assert_eq!(token_hits(false_header.as_bytes()).unwrap().len(), 1);
}

#[test]
fn padding_ends_an_image_without_hiding_the_next_key() {
    let token = key();
    for padding in ["AAA=", "AA=="] {
        let image = format!("{}{padding}", fixture::png(false));
        let text = format!("{{\"image\":\"{image}\",\"text\":\"{token}\"}}\n");
        assert_eq!(token_hits(text.as_bytes()).unwrap().len(), 1);
        let mut state = StreamState::default();
        assert!(record_hits(image.as_bytes(), 1, &mut state)
            .unwrap()
            .is_empty());
        let next = format!("\"\n{token}\n");
        assert_eq!(
            record_hits(next.as_bytes(), 1, &mut state).unwrap().len(),
            1
        );
        assert!(state.finish().is_ok());
    }
}

#[test]
fn image_recognition_survives_every_split_including_the_header() {
    let image = fixture::png(false);
    let token = key();
    for split in 1..image.len() {
        let mut state = StreamState::default();
        let first = record_hits(&image.as_bytes()[..split], 1, &mut state).unwrap();
        assert!(first.is_empty(), "image split: {split}");
        let rest = format!("{}\"\n{token}\n", &image[split..]);
        let second = record_hits(rest.as_bytes(), 1, &mut state).unwrap();
        assert_eq!(second.len(), 1, "image split: {split}");
        assert_eq!(second[0].line, Some(2));
        assert!(rest.as_bytes().get(second[0].span.clone().unwrap()) == Some(token.as_bytes()));
        assert!(state.finish().is_ok());
    }
}

#[test]
fn an_image_signature_inside_another_word_is_not_a_payload_boundary() {
    let image = fixture::png(false);
    let mut state = StreamState::default();
    assert!(record_hits(b"AAAA", 1, &mut state).unwrap().is_empty());
    assert_eq!(
        record_hits(image.as_bytes(), 1, &mut state).unwrap().len(),
        1
    );
    assert_eq!(
        token_hits(format!("AAAA{image}").as_bytes()).unwrap().len(),
        1
    );
}

#[test]
fn a_malformed_continuation_retains_hits_and_makes_the_record_incomplete() {
    let image = fixture::png(false);
    let token = key();
    let mut state = StreamState::default();
    assert!(record_hits(image.as_bytes(), 1, &mut state)
        .unwrap()
        .is_empty());
    let malformed = format!("A\"\n{token}\n");
    let incomplete = record_hits(malformed.as_bytes(), 1, &mut state)
        .err()
        .unwrap();
    assert_eq!(incomplete.reason, "unreadable");
    assert_eq!(incomplete.hits.len(), 1);
    assert!(state.finish().is_err());
}

#[test]
fn image_runs_after_padding_are_not_counted_again_from_every_start() {
    // A run may start after "=" and hold "=". Counted past its padding,
    // each run would count the rest of the input again.
    for repeated in ["iVBO=", "iVBORw0KGgoAAAANSUhEUgAA="] {
        let run = repeated.repeat(256 * 1024 / repeated.len());
        let started = std::time::Instant::now();
        find(run.as_bytes());
        record_hits(run.as_bytes(), 1, &mut StreamState::default()).unwrap();
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(10),
            "checking {} bytes of {repeated} took {took:?}",
            run.len()
        );
    }
}

#[test]
fn an_image_after_an_assignment_or_a_json_escape_is_still_an_image() {
    let image = fixture::png(false);
    for before in ["img=", "Screenshot:\\n", "\\r", "\\t"] {
        let text = format!("{{\"stdout\":\"{before}{image}\"}}\n");
        assert!(token_hits(text.as_bytes()).unwrap().is_empty(), "{before}");
        let mut state = StreamState::default();
        assert!(
            record_hits(text.as_bytes(), 1, &mut state)
                .unwrap()
                .is_empty(),
            "{before}"
        );
    }
    // The escape's backslash ends one record piece and its letter starts
    // the next.
    let mut state = StreamState::default();
    assert!(record_hits(b"{\"stdout\":\"\\", 1, &mut state)
        .unwrap()
        .is_empty());
    let rest = format!("n{image}\"}}\n");
    assert!(record_hits(rest.as_bytes(), 1, &mut state)
        .unwrap()
        .is_empty());
    // Encoded text after padding is not one image, so it is searched.
    let joined = format!("img={image}AAA=AAAA");
    assert_eq!(token_hits(joined.as_bytes()).unwrap().len(), 1);
}
