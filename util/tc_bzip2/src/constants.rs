// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This package is based on the work done by Keiron Liddle, Aftex Software
// <keiron@aftexsw.com> to whom the Ant project is very grateful for his
// great code.

//! BZip2 shared constants.
//!
//! Port of `BZip2Constants.cs` from bc-csharp.

/// Base block size in bytes. Actual block size = `BASE_BLOCK_SIZE * level` (level 1–9),
/// giving a maximum of 900,000 bytes at level 9.
pub(super) const BASE_BLOCK_SIZE: usize = 100_000;

/// Maximum Huffman alphabet size: 256 possible byte values plus the two
/// run-length symbols [`RUNA`] and [`RUNB`].
pub(super) const MAX_ALPHA_SIZE: usize = 258;

/// Maximum Huffman code length allowed during **decoding**.
pub(super) const MAX_CODE_LEN: usize = 20;

/// Maximum Huffman code length allowed during **encoding** (code generation).
/// Kept smaller than [`MAX_CODE_LEN`] so every generated code is guaranteed
/// to be decodable.
pub(super) const MAX_CODE_LEN_GEN: usize = 17;

/// Run-length symbol A. Together with [`RUNB`], encodes the length of a
/// run of repeated bytes using a binary (Fibonacci-like) encoding.
pub(super) const RUNA: usize = 0;

/// Run-length symbol B. See [`RUNA`].
pub(super) const RUNB: usize = 1;

/// Maximum number of Huffman tables used per block.
/// Each segment of [`G_SIZE`] symbols selects one of these tables via a selector.
pub(super) const N_GROUPS: usize = 6;

/// Number of symbols per Huffman group (segment).
/// Every [`G_SIZE`] symbols the active Huffman table may change.
pub(super) const G_SIZE: usize = 50;

/// Number of iterations used to optimise Huffman tables during compression.
/// Frequencies are collected and tables are rebuilt [`N_ITERS`] times to
/// converge toward an optimal assignment.
pub(super) const N_ITERS: usize = 4;

/// Maximum number of selectors in a block.
/// `= 2 + (max_block_size / G_SIZE)` where max block size is 900,000 bytes.
pub(super) const MAX_SELECTORS: usize = 2 + (900_000 / G_SIZE);

/// Number of extra bytes appended beyond the block during BWT sorting to
/// prevent out-of-bounds reads during suffix comparisons.
pub(super) const NUM_OVERSHOOT_BYTES: usize = 20;
