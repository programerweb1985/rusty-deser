# rusty-deser

> High-performance, zero-allocation binary deserialization engine, written in Rust.

`rusty-deser` decodes a compact wire format: a stream of frames, each prefixed
with a 4-byte little-endian length header, followed by an opaque payload blob.
It is built for hot paths — a reusable internal arena avoids per-frame heap
allocations, and payloads are returned as borrowed slices rather than owned
`Vec`s.

## Highlights

- ✅ **Memory-safe public API** — only `&[u8]` in, borrowed slices out.
- ✅ **Audited `unsafe`** — a single, minimal hot-copy block, documented and reviewed.
- ✅ **Checked length arithmetic** — no integer overflows.
- ✅ **No hidden dependencies** — zero crates in the dependency tree.
- ✅ **Frame-count + truncation detection** with descriptive errors.

## Usage

```rust
use rusty_deser::Decoder;

let mut decoder = Decoder::new();
let bytes: &[u8] = &[0x02, 0x00, 0x00, 0x00, b'h', b'i', 0x01, 0x00, 0x00, 0x00, b'!'];
let frames = decoder.decode(bytes).unwrap();
assert_eq!(frames[0].payload, b"hi");
```

Run the included demo:

```bash
cargo run
```

## Wire format

```
+---------------+-------------------+
| u32 LE length | length bytes      |
+---------------+-------------------+
```

Frames are concatenated back-to-back with no padding.

## Safety

This crate's safety claims are covered in [`SECURITY.md`](SECURITY.md). To
report a vulnerability, use GitHub's private vulnerability reporting on the
**Security** tab of this repository.

## License

MIT
