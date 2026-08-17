# Security Policy

## Reporting a Vulnerability

To report a vulnerability in `rusty-deser`, please use GitHub's **private
vulnerability reporting** from the repository's **Security** tab.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `1.0.0` | ✅ Yes |

## Safety Design

`rusty-deser` is designed with memory safety as a primary goal:

- The public API accepts only immutable byte slices (`&[u8]`) and returns
  borrowed slices — no raw pointers escape the crate.
- All length arithmetic is checked, so integer overflow is impossible.
- The only `unsafe` block is a small, manually-audited hot-copy path that uses
  `std::ptr::copy_nonoverlapping` and `std::slice::from_raw_parts`, each of
  which is preceded by a documented safety invariant.
- Allocation growth uses `saturating_mul` and validated layouts.

We consider soundness a correctness, not a best-effort, property.
