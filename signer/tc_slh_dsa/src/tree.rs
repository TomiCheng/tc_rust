use alloc::vec;
use alloc::vec::Vec;

use crate::SlhDsaParameters;
use crate::adrs::{self, Adrs};
use crate::hash::Hasher;

/// Merkle 樹計算時堆疊上的節點。
struct Node {
    value: [u8; 32],
    height: u32,
}

fn copy_type(from: &Adrs, kind: u32) -> Adrs {
    let mut adrs = Adrs::default();
    adrs.0[..16].copy_from_slice(&from.0[..16]);
    adrs.set_type(kind);
    adrs
}

// The base-16 digits of the message and its checksum, FIPS 205 algorithm 7 with lg w = 4
fn wots_digits(p: &SlhDsaParameters, message: &[u8]) -> Vec<u32> {
    let len1 = p.wots_len1();
    let mut digits = Vec::with_capacity(p.wots_len());
    for &byte in &message[..len1 / 2] {
        digits.push(u32::from(byte >> 4));
        digits.push(u32::from(byte & 0x0f));
    }
    let checksum: u32 = digits.iter().map(|&digit| 15 - digit).sum::<u32>() << 4;
    let bytes = checksum.to_be_bytes();
    digits.push(u32::from(bytes[2] >> 4));
    digits.push(u32::from(bytes[2] & 0x0f));
    digits.push(u32::from(bytes[3] >> 4));
    digits
}

/// FIPS 205 的 WOTS+、XMSS、FORS 與 hypertree，以 [`Hasher`] 做雜湊。
pub(crate) struct Tree<'a> {
    p: SlhDsaParameters,
    hasher: &'a Hasher,
    sk_seed: &'a [u8],
}

impl<'a> Tree<'a> {
    pub(crate) fn new(p: SlhDsaParameters, hasher: &'a Hasher, sk_seed: &'a [u8]) -> Self {
        Self { p, hasher, sk_seed }
    }

    fn n(&self) -> usize {
        self.p.n()
    }

    fn chain(&self, start: u32, steps: u32, adrs: &mut Adrs, x: &mut [u8]) {
        for j in 0..steps {
            adrs.set_hash(start + j);
            self.hasher.f(adrs, x);
        }
    }

    // FIPS 205 algorithm 6, wots_pkGen
    fn wots_pk_gen(&self, param: &Adrs, out: &mut [u8]) {
        let n = self.n();
        let mut chains = vec![0u8; self.p.wots_len() * n];
        for (i, chunk) in chains.chunks_exact_mut(n).enumerate() {
            let mut adrs = *param;
            adrs.set_type_and_clear(adrs::WOTS_PRF);
            adrs.set_key_pair(param.key_pair());
            adrs.set_chain(i as u32);
            self.hasher.prf(&adrs, self.sk_seed, chunk);
            adrs.set_type_and_clear(adrs::WOTS_HASH);
            adrs.set_key_pair(param.key_pair());
            adrs.set_chain(i as u32);
            self.chain(0, 15, &mut adrs, chunk);
        }
        let mut pk_adrs = *param;
        pk_adrs.set_type_and_clear(adrs::WOTS_PK);
        pk_adrs.set_key_pair(param.key_pair());
        self.hasher.t_l(&pk_adrs, &chains, out);
    }

    // FIPS 205 algorithm 7, wots_sign
    fn wots_sign(&self, message: &[u8], param: &Adrs, out: &mut [u8]) {
        let n = self.n();
        let digits = wots_digits(&self.p, message);
        for (i, chunk) in out.chunks_exact_mut(n).take(digits.len()).enumerate() {
            let mut adrs = *param;
            adrs.set_type_and_clear(adrs::WOTS_PRF);
            adrs.set_key_pair(param.key_pair());
            adrs.set_chain(i as u32);
            self.hasher.prf(&adrs, self.sk_seed, chunk);
            adrs.set_type_and_clear(adrs::WOTS_HASH);
            adrs.set_key_pair(param.key_pair());
            adrs.set_chain(i as u32);
            self.chain(0, digits[i], &mut adrs, chunk);
        }
    }

    // FIPS 205 algorithm 8, wots_pkFromSig
    fn wots_pk_from_sig(&self, sig: &[u8], message: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.n();
        let digits = wots_digits(&self.p, message);
        let mut chains = sig[..digits.len() * n].to_vec();
        for (i, chunk) in chains.chunks_exact_mut(n).enumerate() {
            adrs.set_chain(i as u32);
            self.chain(digits[i], 15 - digits[i], adrs, chunk);
        }
        let mut pk_adrs = *adrs;
        pk_adrs.set_type_and_clear(adrs::WOTS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.hasher.t_l(&pk_adrs, &chains, out);
    }

    // FIPS 205 algorithm 9, xmss_node, as a stack over the leaves from s
    fn xmss_root(&self, s: u32, z: usize, param: &Adrs, out: &mut [u8]) {
        let n = self.n();
        let mut stack: Vec<Node> = Vec::new();
        let mut adrs = *param;
        for idx in 0..1u32 << z {
            let mut node = Node {
                value: [0; 32],
                height: 1,
            };
            adrs.set_type_and_clear(adrs::WOTS_HASH);
            adrs.set_key_pair(s + idx);
            self.wots_pk_gen(&adrs, &mut node.value[..n]);
            adrs.set_type_and_clear(adrs::TREE);
            adrs.set_tree_height(1);
            adrs.set_tree_index(s + idx);
            let mut index = s + idx;
            while stack.last().is_some_and(|top| top.height == node.height) {
                let top = stack.pop().expect("a node");
                index = (index - 1) / 2;
                adrs.set_tree_index(index);
                let right = node.value;
                self.hasher
                    .h(&adrs, &top.value[..n], &right[..n], &mut node.value[..n]);
                node.height += 1;
                adrs.set_tree_height(node.height);
            }
            stack.push(node);
        }
        out.copy_from_slice(&stack.last().expect("a root").value[..n]);
    }

    // FIPS 205 algorithm 10, xmss_sign
    fn xmss_sign(&self, message: &[u8], idx: u32, param: &Adrs, sig: &mut [u8]) {
        let n = self.n();
        let wots_bytes = self.p.wots_len() * n;
        let mut adrs = copy_type(param, adrs::WOTS_HASH);
        adrs.set_key_pair(idx);
        self.wots_sign(message, &adrs, &mut sig[..wots_bytes]);
        let tree_adrs = copy_type(param, adrs::TREE);
        for j in 0..self.p.h_prime() {
            let k = (idx >> j) ^ 1;
            let at = wots_bytes + j * n;
            self.xmss_root(k << j, j, &tree_adrs, &mut sig[at..at + n]);
        }
    }

    // FIPS 205 algorithm 11, xmss_pkFromSig
    fn xmss_pk_from_sig(&self, idx: u32, sig: &[u8], message: &[u8], param: &Adrs) -> [u8; 32] {
        let n = self.n();
        let wots_bytes = self.p.wots_len() * n;
        let mut adrs = copy_type(param, adrs::WOTS_HASH);
        adrs.set_key_pair(idx);
        let mut node = [0u8; 32];
        self.wots_pk_from_sig(sig, message, &mut adrs, &mut node[..n]);
        adrs.set_type_and_clear(adrs::TREE);
        adrs.set_tree_index(idx);
        for k in 0..self.p.h_prime() {
            adrs.set_tree_height(k as u32 + 1);
            let auth = &sig[wots_bytes + k * n..wots_bytes + (k + 1) * n];
            let current = node;
            if (idx >> k) & 1 == 0 {
                adrs.set_tree_index(adrs.tree_index() / 2);
                self.hasher.h(&adrs, &current[..n], auth, &mut node[..n]);
            } else {
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                self.hasher.h(&adrs, auth, &current[..n], &mut node[..n]);
            }
        }
        node
    }

    fn xmss_bytes(&self) -> usize {
        (self.p.h_prime() + self.p.wots_len()) * self.n()
    }

    fn ht_offset(&self) -> usize {
        ((self.p.a() + 1) * self.p.k() + 1) * self.n()
    }

    /// FIPS 205 演算法 18 的 PK.root：最上層 XMSS 樹的根。
    pub(crate) fn ht_root(&self, out: &mut [u8]) {
        let mut adrs = Adrs::default();
        adrs.set_layer(self.p.d() as u32 - 1);
        self.xmss_root(0, self.p.h_prime(), &adrs, out);
    }

    /// FIPS 205 演算法 12，ht_sign：簽在 `sig` 的 SIG_HT 位置。
    pub(crate) fn ht_sign(&self, message: &[u8], mut tree: u64, mut leaf: u32, sig: &mut [u8]) {
        let n = self.n();
        let step = self.xmss_bytes();
        let mut pos = self.ht_offset();
        let mut adrs = Adrs::default();
        adrs.set_tree(tree);
        self.xmss_sign(message, leaf, &adrs, &mut sig[pos..pos + step]);
        let mut root = self.xmss_pk_from_sig(leaf, &sig[pos..pos + step], message, &adrs);
        let mask = (1u64 << self.p.h_prime()) - 1;
        for j in 1..self.p.d() {
            pos += step;
            leaf = (tree & mask) as u32;
            tree >>= self.p.h_prime();
            adrs.set_layer(j as u32);
            adrs.set_tree(tree);
            self.xmss_sign(&root[..n], leaf, &adrs, &mut sig[pos..pos + step]);
            if j < self.p.d() - 1 {
                root = self.xmss_pk_from_sig(leaf, &sig[pos..pos + step], &root[..n], &adrs);
            }
        }
    }

    /// FIPS 205 演算法 13，ht_verify。變動時間：只處理公開值。
    pub(crate) fn ht_verify(
        &self,
        message: &[u8],
        sig: &[u8],
        mut tree: u64,
        mut leaf: u32,
        root: &[u8],
    ) -> bool {
        let n = self.n();
        let step = self.xmss_bytes();
        let mut pos = self.ht_offset();
        let mut adrs = Adrs::default();
        adrs.set_tree(tree);
        let mut node = self.xmss_pk_from_sig(leaf, &sig[pos..pos + step], message, &adrs);
        let mask = (1u64 << self.p.h_prime()) - 1;
        for j in 1..self.p.d() {
            pos += step;
            leaf = (tree & mask) as u32;
            tree >>= self.p.h_prime();
            adrs.set_layer(j as u32);
            adrs.set_tree(tree);
            node = self.xmss_pk_from_sig(leaf, &sig[pos..pos + step], &node[..n], &adrs);
        }
        &node[..n] == root
    }

    fn fors_indices(&self, digest: &[u8]) -> Vec<u32> {
        let a = self.p.a();
        let mut indices = Vec::with_capacity(self.p.k());
        let (mut bits, mut value, mut pos) = (0usize, 0u32, 0usize);
        for _ in 0..self.p.k() {
            while bits < a {
                value = (value << 8) | u32::from(digest[pos]);
                pos += 1;
                bits += 8;
            }
            bits -= a;
            indices.push((value >> bits) & ((1 << a) - 1));
        }
        indices
    }

    // FIPS 205 algorithm 15, fors_node, as a stack over the leaves from s
    fn fors_root(&self, s: u32, z: usize, param: &Adrs, out: &mut [u8]) {
        let n = self.n();
        let mut stack: Vec<Node> = Vec::new();
        let mut adrs = *param;
        for idx in 0..1u32 << z {
            let mut node = Node {
                value: [0; 32],
                height: 1,
            };
            adrs.set_type_and_clear(adrs::FORS_PRF);
            adrs.set_key_pair(param.key_pair());
            adrs.set_tree_index(s + idx);
            self.hasher.prf(&adrs, self.sk_seed, &mut node.value[..n]);
            adrs.set_type(adrs::FORS_TREE);
            self.hasher.f(&adrs, &mut node.value[..n]);
            adrs.set_tree_height(1);
            let mut index = s + idx;
            while stack.last().is_some_and(|top| top.height == node.height) {
                let top = stack.pop().expect("a node");
                index = (index - 1) / 2;
                adrs.set_tree_index(index);
                let right = node.value;
                self.hasher
                    .h(&adrs, &top.value[..n], &right[..n], &mut node.value[..n]);
                node.height += 1;
                adrs.set_tree_height(node.height);
            }
            stack.push(node);
        }
        out.copy_from_slice(&stack.last().expect("a root").value[..n]);
    }

    /// FIPS 205 演算法 16，fors_sign：簽在 `sig` 的 SIG_FORS 位置。
    pub(crate) fn fors_sign(&self, digest: &[u8], param: &Adrs, sig: &mut [u8]) {
        let (n, a) = (self.n(), self.p.a());
        let mut pos = n;
        let mut adrs = *param;
        for (i, index) in self.fors_indices(digest).into_iter().enumerate() {
            let i = i as u32;
            adrs.set_type_and_clear(adrs::FORS_PRF);
            adrs.set_key_pair(param.key_pair());
            adrs.set_tree_index((i << a) + index);
            self.hasher.prf(&adrs, self.sk_seed, &mut sig[pos..pos + n]);
            pos += n;
            adrs.set_type(adrs::FORS_TREE);
            for j in 0..a {
                let s = (index >> j) ^ 1;
                self.fors_root((i << a) + (s << j), j, &adrs, &mut sig[pos..pos + n]);
                pos += n;
            }
        }
    }

    /// FIPS 205 演算法 17，fors_pkFromSig。
    pub(crate) fn fors_pk_from_sig(&self, sig: &[u8], digest: &[u8], param: &Adrs, out: &mut [u8]) {
        let (n, a) = (self.n(), self.p.a());
        let mut roots = vec![0u8; self.p.k() * n];
        let mut pos = n;
        let mut adrs = *param;
        for (i, index) in self.fors_indices(digest).into_iter().enumerate() {
            let root = &mut roots[i * n..(i + 1) * n];
            let mut tree_index = ((i as u32) << a) + index;
            adrs.set_tree_height(0);
            adrs.set_tree_index(tree_index);
            root.copy_from_slice(&sig[pos..pos + n]);
            pos += n;
            self.hasher.f(&adrs, root);
            for j in 0..a {
                adrs.set_tree_height(j as u32 + 1);
                let auth = &sig[pos..pos + n];
                let mut current = [0u8; 32];
                current[..n].copy_from_slice(root);
                if (index >> j) & 1 == 0 {
                    tree_index /= 2;
                    adrs.set_tree_index(tree_index);
                    self.hasher.h(&adrs, &current[..n], auth, root);
                } else {
                    tree_index = (tree_index - 1) / 2;
                    adrs.set_tree_index(tree_index);
                    self.hasher.h(&adrs, auth, &current[..n], root);
                }
                pos += n;
            }
        }
        let mut pk_adrs = copy_type(&adrs, adrs::FORS_PK);
        pk_adrs.set_key_pair(adrs.key_pair());
        self.hasher.t_l(&pk_adrs, &roots, out);
    }
}
