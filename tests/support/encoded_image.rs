/// Valid one-pixel PNGs with a private ancillary chunk whose base64 text
/// happens to contain a synthetic Alibaba-shaped value. The large image's
/// chunk has 4,500,000 extra zero bytes, crossing the record reader's cut.
pub fn png(long: bool) -> String {
    let (prefix, padding, suffix) = if long {
        (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAESqM2xvS3MA",
            6_000_000,
            "//bPcJPQAAAAtJREFUeJxjYAACAAAFAAF6Xqs/AAAAAElFTkSuQmCC",
        )
    } else {
        (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAE2xvS3MA",
            0,
            "//0NvY8AAAAAtJREFUeJxjYAACAAAFAAF6Xqs/AAAAAElFTkSuQmCC",
        )
    };
    [
        prefix,
        &"A".repeat(padding),
        "/",
        "LTAI",
        "0123456789abcdefG",
        suffix,
    ]
    .concat()
}
