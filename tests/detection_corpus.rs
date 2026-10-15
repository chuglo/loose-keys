#[path = "support/detection.rs"]
mod detection;
#[path = "support/fixture_body.rs"]
mod fixture_body;

#[test]
fn cli_matches_shared_detection_corpus() {
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_loose-keys"));
    for case in detection::cases() {
        for positive in [true, false] {
            let fixture = detection::Fixture::new(&case, positive);
            fixture.cli(binary, &case, positive);
        }
    }
}
