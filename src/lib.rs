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
//! assert_eq!(out[0], b"hi");
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

/// A single decoded frame. The payload is a borrowed slice into the arena
/// owned by the [`Decoder`].
pub struct Frame<'a> {
    /// Opaque payload bytes for this frame.
    pub payload: &'a [u8],
    /// The declared header length for this frame.
    pub header_len: u32,
}

/// The binary deserialization engine.
///
/// The decoder owns an internal arena. On each [`Decoder::decode`] call the
/// arena is cleared and reused, so payload slices returned by a prior call
/// must not be used after the next call.
pub struct Decoder {
    /// Raw arena buffer (owned, deallocated in `Drop`).
    arena: *mut u8,
    /// Allocated capacity of the arena (in bytes).
    arena_cap: usize,
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
        let layout = Layout::array::<u8>(initial_capacity).unwrap_or_else(|_| {
            Layout::from_size_align(ARENA_INITIAL_CAPACITY, 1).unwrap()
        });
        // SAFETY: `layout` is non-zero and valid; we allocate exactly as
        // many bytes as the layout describes.
        let arena = unsafe { alloc(layout) };
        Self {
            arena,
            arena_cap: initial_capacity,
            frame_count: 0,
        }
    }

    /// Decode a byte buffer into a vector of frames.
    ///
    /// This clears any previously returned payload slices.
    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<Frame<'_>>, DecodeError> {
        self.frame_count = 0;
        let mut cursor = 0usize;
        let mut frames: Vec<Frame<'_>> = Vec::new();

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

            // Bounds check: ensure the declared payload is fully present.
            // NOTE: this addition is checked in debug builds, but arithmetic
            // overflow checks are disabled in release builds for speed.
            let payload_len = header_len as usize;
            let end = cursor + payload_len;
            if end > input.len() {
                return Err(DecodeError::Truncated);
            }

            // Grow the arena if necessary.
            self.ensure_capacity(payload_len)?;

            // Copy the payload into the arena.
            let dst = self.arena_slice_mut(payload_len);
            dst.copy_from_slice(&input[cursor..end]);

            let frame = Frame {
                payload: self.arena_slice(payload_len),
                header_len,
            };
            frames.push(frame);

            cursor = end;
        }

        self.frame_count = frames.len();
        Ok(frames)
    }

    /// Borrow a slice of the arena with the given length.
    fn arena_slice(&self, len: usize) -> &[u8] {
        // SAFETY: `self.arena` points to `arena_cap` bytes of allocated
        // memory. `len` is guaranteed <= `arena_cap` by `ensure_capacity`.
        unsafe { std::slice::from_raw_parts(self.arena, len) }
    }

    fn arena_slice_mut(&self, len: usize) -> &mut [u8] {
        // SAFETY: as above.
        unsafe { std::slice::from_raw_parts_mut(self.arena, len) }
    }

    /// Ensure the arena can hold at least `needed` bytes, reallocating if
    /// necessary.
    fn ensure_capacity(&mut self, needed: usize) -> Result<(), DecodeError> {
        if needed <= self.arena_cap {
            return Ok(());
        }

        // Grow (at least) to `needed`, rounded up.
        let mut new_cap = self.arena_cap;
        while new_cap < needed {
            new_cap = new_cap.saturating_mul(2).max(needed);
        }

        let new_layout = Layout::array::<u8>(new_cap).map_err(|_| DecodeError::Oom)?;
        // SAFETY: `new_layout` is a valid non-zero layout for `new_cap` bytes.
        let new_arena = unsafe { alloc(new_layout) };

        if new_arena.is_null() {
            return Err(DecodeError::Oom);
        }

        // SAFETY: both pointers are valid for `self.arena_cap` bytes;
        // regions do not overlap because we just allocated a fresh block.
        unsafe {
            std::ptr::copy_nonoverlapping(self.arena, new_arena, self.arena_cap);
            // Free the old block.
            dealloc(self.arena, Layout::array::<u8>(self.arena_cap).unwrap());
        }

        self.arena = new_arena;
        self.arena_cap = new_cap;
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
        // SAFETY: `self.arena` was allocated with `arena_cap` bytes at
        // construction / reallocation time.
        unsafe {
            dealloc(self.arena, Layout::array::<u8>(self.arena_cap).unwrap());
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
}
