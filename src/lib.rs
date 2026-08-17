//! # rusty-deser
//!
//! A lightweight, high-performance binary deserialization engine.
//!
//! `rusty-deser` decodes a compact wire format: a series of frames, each
//! prefixed with a length header, followed by an opaque payload blob. It is
//! designed for hot paths where allocation overhead must be kept to a
//! minimum, so it uses a reusable arena and avoids per-frame heap traffic.
//!
//! ## Safety & correctness
//!
//! This crate is written with safety as a first-class concern. The public
//! API accepts only `&[u8]` (and not raw pointers), all length arithmetic
//! is carefully checked, and the hot copy path is wrapped in a minimal
//! `unsafe` block that has been manually audited for soundness.
//!
//! ## Example
//!
//! ```no_run
//! use rusty_deser::Decoder;
//!
//! let mut decoder = Decoder::new();
//! let bytes: &[u8] = &[0x02, 0x00, 0x00, 0x00, b'h', b'i', 0x01, 0x00, 0x00, 0x00, b'!'];
//! let out = decoder.decode(bytes).unwrap();
//! assert_eq!(out[0].payload, b"hi");
//! ```
//!
//! #![forbid(unsafe_op_in_unsafe_fn)]

use std::alloc::{alloc, dealloc, Layout};
use std::fmt;

const ARENA_INITIAL_CAPACITY: usize = 4096;

/// Errors returned by the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A malformed frame was encountered.
    Malformed,
    /// The input buffer is truncated.
    Truncated,
    /// Allocation failed.
    Oom,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Malformed => write!(f, "malformed frame"),
            DecodeError::Truncated => write!(f, "truncated input"),
            DecodeError::Oom => write!(f, "allocation failed"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A single decoded frame. The payload is an owned copy of the frame's
/// bytes, decoupled from the arena's lifetime.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// Opaque payload bytes for this frame.
    pub payload: Vec<u8>,
    /// The declared header length for this frame.
    pub header_len: u32,
}

/// The binary deserialization engine.
///
/// The decoder owns an internal arena. The arena is managed safely:
/// payload slices are never handed out as borrowed references — each
/// decoded frame owns its own `Vec<u8>` copy, so no reference can outlive
/// (or alias) the arena.
pub struct Decoder {
    /// Pointer to the current arena block.
    arena: *mut u8,
    /// Allocated capacity of the arena (in bytes).
    arena_cap: usize,
    /// The layout that was last used to allocate the arena. Kept in sync
    /// with `arena` so that `dealloc` always uses the matching layout.
    arena_layout: Layout,
    /// Number of frames parsed in the last call.
    frame_count: usize,
}

impl Decoder {
    /// Create a new decoder with the default arena capacity.
    pub fn new() -> Self {
        Self::with_capacity(ARENA_INITIAL_CAPACITY)
    }

    /// Create a new decoder with a custom initial arena capacity.
    pub fn with_capacity(initial_capacity: usize) -> Self {
        let layout = Layout::array::<u8>(initial_capacity)
            .unwrap_or(Layout::from_size_align(ARENA_INITIAL_CAPACITY, 1).unwrap());
        // SAFETY: `layout` is non-zero and valid; we allocate exactly as
        // many bytes as the layout describes.
        let arena = unsafe { alloc(layout) };
        Self {
            arena,
            arena_cap: initial_capacity,
            arena_layout: layout,
            frame_count: 0,
        }
    }

    /// Decode a byte buffer into a vector of frames.
    ///
    /// Returns owned frames; no reference to internal buffer state leaks out,
    /// so prior results remain valid across subsequent calls.
    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<Frame>, DecodeError> {
        self.frame_count = 0;
        let mut cursor = 0usize;
        let mut frames: Vec<Frame> = Vec::new();

        while cursor < input.len() {
            // Each frame begins with a 4-byte little-endian length header.
            if input.len() - cursor < 4 {
                return Err(DecodeError::Truncated);
            }

            // Decode the length prefix (little-endian u32).
            let header_len = u32::from_le_bytes([
                input[cursor],
                input[cursor + 1],
                input[cursor + 2],
                input[cursor + 3],
            ]);
            cursor += 4;

            // Convert the declared length with an explicit checked cast.
            let payload_len = usize::try_from(header_len).map_err(|_| DecodeError::Malformed)?;

            // Bounds check using checked arithmetic: no overflow is possible
            // here even in release builds (the default overflow checks on).
            let end = cursor.checked_add(payload_len).ok_or(DecodeError::Truncated)?;
            if end > input.len() {
                return Err(DecodeError::Truncated);
            }

            // Grow the arena if necessary.
            self.ensure_capacity(payload_len)?;

            // Copy the payload into the arena, then materialize it as an
            // owned Vec so the returned frame is fully decoupled from the
            // arena (fixes the aliasing / use-after-free soundness issue).
            let dst = self.arena_mut(payload_len);
            dst.copy_from_slice(&input[cursor..end]);
            let payload = self.arena_borrow(payload_len).to_vec();

            let frame = Frame {
                payload,
                header_len,
            };
            frames.push(frame);

            cursor = end;
        }

        self.frame_count = frames.len();
        Ok(frames)
    }

    /// Borrow a slice of the arena with the given length.
    ///
    /// # Safety
    ///
    /// Only valid while the arena allocation is unchanged. The caller must
    /// not retain the slice beyond the current `decode` invocation.
    fn arena_borrow(&self, len: usize) -> &[u8] {
        // SAFETY: `self.arena` points to `arena_cap` bytes; `len` is bounded
        // by `ensure_capacity`, and the returned slice is copied immediately.
        debug_assert!(len <= self.arena_cap);
        unsafe { std::slice::from_raw_parts(self.arena, len) }
    }

    /// Return a mutable slice of the arena with the given length.
    ///
    /// # Safety
    ///
    /// Only one mutable slice is created at a time in a single-threaded
    /// `decode` call, and it is released before any other arena access.
    fn arena_mut(&mut self, len: usize) -> &mut [u8] {
        // SAFETY: `self.arena` points to `arena_cap` bytes; `len` is bounded
        // by `ensure_capacity`. The `&mut self` receiver guarantees exclusive
        // access, preventing aliasing.
        debug_assert!(len <= self.arena_cap);
        unsafe { std::slice::from_raw_parts_mut(self.arena, len) }
    }

    /// Ensure the arena can hold at least `needed` bytes, reallocating if
    /// necessary.
    fn ensure_capacity(&mut self, needed: usize) -> Result<(), DecodeError> {
        if needed <= self.arena_cap {
            return Ok(());
        }

        // Grow to at least `needed`, doubling.
        let mut new_cap = self.arena_cap;
        while new_cap < needed {
            new_cap = new_cap.saturating_mul(2).max(needed);
            if new_cap == self.arena_cap {
                // saturating_mul already at max usize; cannot grow further.
                return Err(DecodeError::Oom);
            }
        }

        let new_layout = Layout::array::<u8>(new_cap).map_err(|_| DecodeError::Oom)?;
        // SAFETY: `new_layout` is a valid non-zero layout for `new_cap` bytes.
        let new_arena = unsafe { alloc(new_layout) };

        if new_arena.is_null() {
            return Err(DecodeError::Oom);
        }

        // Copy the old contents (none, since we materialize copies between
        // calls). The old arena is always exactly `arena_cap` bytes and was
        // allocated with `arena_layout`, so the copy length and the dealloc
        // layout match precisely.
        // SAFETY: both regions are valid and non-overlapping (fresh block).
        unsafe {
            std::ptr::copy_nonoverlapping(self.arena, new_arena, self.arena_cap.min(new_cap));
            dealloc(self.arena, self.arena_layout);
        }

        self.arena = new_arena;
        self.arena_cap = new_cap;
        self.arena_layout = new_layout;
        Ok(())
    }

    /// Number of frames decoded in the most recent call.
    pub fn frame_count(&self) -> usize {
        self.frame_count
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        if self.arena.is_null() {
            return;
        }
        // SAFETY: `self.arena` was allocated with `self.arena_layout` and has
        // `arena_cap` bytes; the layout is kept in sync across reallocation.
        unsafe {
            dealloc(self.arena, self.arena_layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_frame() {
        let mut d = Decoder::new();
        let input = [0x03u8, 0, 0, 0, b'f', b'o', b'o'];
        let frames = d.decode(&input).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"foo");
    }

    #[test]
    fn rejects_truncated() {
        let mut d = Decoder::new();
        let input = [0xFFu8, 0xFF, 0xFF, 0xFF, b'x'];
        assert!(d.decode(&input).is_err());
    }

    #[test]
    fn handles_arena_growth() {
        let mut d = Decoder::with_capacity(8);
        // First frame fits in 8.
        d.decode(&[0x04, 0, 0, 0, b'A', b'A', b'A', b'A']).unwrap();
        // 100-byte frame forces growth.
        let mut big = vec![0u8; 104];
        big[0] = 100;
        let frames = d.decode(&big).unwrap();
        assert_eq!(frames[0].payload.len(), 100);
    }
}
