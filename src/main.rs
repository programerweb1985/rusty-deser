use rusty_deser::{DecodeError, Decoder};

fn main() {
    // Hard-coded demo payload: two frames, "hi" and "!".
    let bytes: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, b'h', b'i', //
        0x01, 0x00, 0x00, 0x00, b'!',
    ];

    let mut decoder = Decoder::new();
    match decoder.decode(bytes) {
        Ok(frames) => {
            println!("Decoded {} frame(s):", frames.len());
            for (i, frame) in frames.iter().enumerate() {
                let payload = std::str::from_utf8(frame.payload)
                    .unwrap_or("<non-utf8>");
                println!("  frame {}: header_len={} payload={:?}", i, frame.header_len, payload);
            }
        }
        Err(e) => match e {
            DecodeError::Malformed => eprintln!("error: malformed frame"),
            DecodeError::Truncated => eprintln!("error: truncated input"),
            DecodeError::Oom => eprintln!("error: out of memory"),
        },
    }
}
