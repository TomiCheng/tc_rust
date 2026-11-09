use crate::adrs::{self, Adrs};
use crate::hash::Hasher;
use crate::tree::Tree;
use crate::{SlhDsaPrivateKey, SlhDsaPublicKey};

/// FIPS 205 演算法 19，slh_sign_internal：`message` 是 M′，`opt_rand` 是 n 位元組。
pub(crate) fn sign(key: &SlhDsaPrivateKey, message: &[u8], opt_rand: &[u8], sig: &mut [u8]) {
    let p = key.params();
    let n = p.n();
    let public = key.public();
    let hasher = Hasher::new(p, public.seed());
    let (r, _) = sig.split_at_mut(n);
    hasher.prf_msg(key.sk_prf(), opt_rand, message, r);
    let indexed = hasher.h_msg(&sig[..n], public.root(), message);

    let mut adrs = Adrs::default();
    adrs.set_type(adrs::FORS_TREE);
    adrs.set_tree(indexed.tree);
    adrs.set_key_pair(indexed.leaf);
    let tree = Tree::new(p, &hasher, key.sk_seed());
    tree.fors_sign(&indexed.digest, &adrs, sig);
    let mut pk_fors = [0u8; 32];
    tree.fors_pk_from_sig(sig, &indexed.digest, &adrs, &mut pk_fors[..n]);
    tree.ht_sign(&pk_fors[..n], indexed.tree, indexed.leaf, sig);
}

/// FIPS 205 演算法 20，slh_verify_internal。變動時間：只能用於公開值。
pub(crate) fn verify(key: &SlhDsaPublicKey, message: &[u8], sig: &[u8]) -> bool {
    let p = key.params();
    if sig.len() != p.signature_length() {
        return false;
    }
    let n = p.n();
    let hasher = Hasher::new(p, key.seed());
    let indexed = hasher.h_msg(&sig[..n], key.root(), message);
    let mut adrs = Adrs::default();
    adrs.set_type(adrs::FORS_TREE);
    adrs.set_tree(indexed.tree);
    adrs.set_key_pair(indexed.leaf);
    let tree = Tree::new(p, &hasher, &[]);
    let mut pk_fors = [0u8; 32];
    tree.fors_pk_from_sig(sig, &indexed.digest, &adrs, &mut pk_fors[..n]);
    tree.ht_verify(&pk_fors[..n], sig, indexed.tree, indexed.leaf, key.root())
}
