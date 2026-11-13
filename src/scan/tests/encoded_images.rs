use super::*;

use crate::encoded_image_fixture as fixture;

#[test]
fn encoded_images_are_not_tokens_in_scans_or_rechecks() {
    let f = Fixture::new("encoded-images");
    let image = fixture::png(false);
    let path = f.0.join(".claude/projects/fixture/session.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // A tool receipt can keep a second copy outside the message's image block.
    let record = serde_json::json!({
        "toolUseResult": {"base64": image},
        "message": {"content": [{"type": "image", "source": {
            "type": "base64", "media_type": "image/png", "data": image
        }}]},
        "uri": format!("data:image/png;base64,{image}")
    });
    fs::write(&path, format!("{record}\n")).unwrap();
    let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
    assert!(scan.findings.is_empty(), "encoded image text was reported");
    assert!(scan.not_checked.is_empty(), "image caused a scan gap");
    for rule in ["secret.agent-record", "secret.service-token"] {
        let still = recheck(rule, &path, &f.0, None).expect("recheck should complete");
        assert!(still.is_empty(), "encoded image text survived recheck");
    }
}

#[test]
fn encoded_images_across_record_pieces_keep_neighboring_keys_and_lines() {
    let f = Fixture::new("encoded-images-long");
    let key = ["LTAI", "0123456789abcdefghij"].concat();
    let image = fixture::png(true);
    let record = format!("{{\"source\":{{\"data\":\"{image}\"}}}}\n\n{{\"text\":\"{key}\"}}\n");
    let path = f.0.join(".claude/projects/fixture/session.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, record).unwrap();
    let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
    assert!(scan.not_checked.is_empty(), "long image caused a gap");
    assert_eq!(scan.findings.len(), 1, "only the text key should be listed");
    assert_eq!(scan.findings[0].rule, "secret.agent-record");
    assert_eq!(scan.findings[0].line, Some(3));
    let still = recheck("secret.agent-record", &path, &f.0, None).unwrap();
    assert_eq!(still.len(), 1, "scan and recheck should find the same key");
    let output = crate::report::to_ascii_json(&Scan::report_excluding(
        &f.0,
        std::slice::from_ref(&f.0),
        &[],
    ));
    for piece in key.as_bytes().windows(10) {
        assert!(!output.as_bytes().windows(10).any(|part| part == piece));
    }
}

#[test]
fn malformed_images_after_a_record_cut_are_gaps_and_cannot_resolve_findings() {
    let f = Fixture::new("encoded-images-malformed");
    let path = f.0.join(".claude/projects/fixture/session.jsonl");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    for delimiter in ["\"}\n", ""] {
        // An extra character leaves an incomplete base64 quartet. The
        // header and earlier pieces were already recognized as image data.
        let record = format!("{{\"data\":\"{}A{delimiter}", fixture::png(true));
        fs::write(&path, record).unwrap();
        let scan = Scan::run(&f.0, std::slice::from_ref(&f.0));
        assert!(scan
            .not_checked
            .iter()
            .any(|gap| gap.reason == "unreadable"));
        assert!(recheck("secret.agent-record", &path, &f.0, None).is_none());
    }
}
