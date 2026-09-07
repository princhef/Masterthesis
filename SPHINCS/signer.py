#!/usr/bin/env python3
"""
Reference SPHINCS+ signer for tweaked variants from ePrint 2025/2203.
Produces valid signatures verifiable by the Solidity/Assembly contracts.

Usage:
    python3 script/signer.py <variant> <message_hex>
    variant: c1 | c2 | c3 | c4
    message_hex: 0x-prefixed 32-byte hex

Output: ABI-encoded (bytes32 seed, bytes32 root, bytes sig) as hex to stdout.
"""

import sys
import struct
import time
import multiprocessing
from Crypto.Hash import keccak as _keccak_mod

from eth_account import Account
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_utils import keccak
from coincurve import PrivateKey
import time
import rlp

# ============================================================
#  Constants
# ============================================================

N = 16  # n = 128 bits = 16 bytes
N_MASK = (1 << 256) - (1 << 128)  # top 128 bits of uint256
FULL = (1 << 256) - 1

ADRS_WOTS = 0
ADRS_WOTS_PK = 1
ADRS_TREE = 2
ADRS_FORS_TREE = 3
ADRS_FORS_ROOTS = 4
ADRS_PORS = 5

W = 16
LOG_W = 4
L = 32
LEN1 = 32
TARGET_SUM = 240
Z = 0
W_MASK = 0xF

VARIANTS = {
    "c2": {"h": 18, "d": 2, "k": 13, "a": 13, "m_max": 0,   "scheme": "fors",
            "subtree_h": 9, "sig_size": 4040},
    "c6": {"h": 24, "d": 2, "k": 8, "a": 16, "m_max": 0, "scheme": "fors",
            "subtree_h": 12, "sig_size": 3352},
    "c7": {"h": 24, "d": 2, "k": 8, "a": 16, "m_max": 0, "scheme": "fors",
            "subtree_h": 12, "sig_size": 3704,
            "w": 8, "log_w": 3, "l": 43, "len1": 43, "target_sum": 151, "w_mask": 0x7,
            "adrs_mode": "fips",      # migrated to FIPS 205 uncompressed ADRS
            "fors_bind_leaf": True},  # key FORS instance by per-message hypertree leaf (FIPS field split)
    "c8": {"h": 20, "d": 2, "k": 12, "a": 13, "m_max": 0, "scheme": "fors",
            "subtree_h": 10, "sig_size": 3848,
            "w": 16, "log_w": 4, "l": 32, "len1": 32, "target_sum": 162, "w_mask": 0xF},
    "c9": {"h": 20, "d": 2, "k": 11, "a": 12, "m_max": 0, "scheme": "fors",
            "subtree_h": 10, "sig_size": 3816,
            "w": 8, "log_w": 3, "l": 43, "len1": 43, "target_sum": 208, "w_mask": 0x7,
            "adrs_mode": "fips",      # migrated to FIPS 205 uncompressed ADRS
            "fors_bind_leaf": True},  # key FORS instance by per-message hypertree leaf (FIPS field split)
    "c10": {"h": 18, "d": 2, "k": 13, "a": 11, "m_max": 0, "scheme": "fors",
            "subtree_h": 9, "sig_size": 4008,
            "w": 8, "log_w": 3, "l": 43, "len1": 43, "target_sum": 205, "w_mask": 0x7},
    "c11": {"h": 16, "d": 2, "k": 13, "a": 11, "m_max": 0, "scheme": "fors",
            "subtree_h": 8, "sig_size": 3976,
            "w": 8, "log_w": 3, "l": 43, "len1": 43, "target_sum": 203, "w_mask": 0x7,
            "fors_bind_leaf": True},  # key FORS instance by per-message hypertree leaf (FIPS field split)
    "c13": {"h": 22, "d": 2, "k": 7, "a": 19, "m_max": 0, "scheme": "fors",
            "subtree_h": 11, "sig_size": 3688,
            "w": 8, "log_w": 3, "l": 43, "len1": 43, "target_sum": 208, "w_mask": 0x7,
            "adrs_mode": "fips",      # FIPS 205 §11.2.2 uncompressed 32-byte ADRS
            "fors_bind_leaf": True},  # key FORS instance by per-message hypertree leaf (FIPS field split)
}

# ============================================================
#  Keccak256 Primitive (optimized: minimize object creation)
# ============================================================

def keccak256(data: bytes) -> int:
    h = _keccak_mod.new(digest_bits=256)
    h.update(data)
    return int.from_bytes(h.digest(), "big")

def to_b32(val: int) -> bytes:
    return (val & FULL).to_bytes(32, "big")

def to_b4(val: int) -> bytes:
    return struct.pack(">I", val & 0xFFFFFFFF)

# Pre-allocate buffer for hot-path hashing
_BUF96 = bytearray(96)
_BUF128 = bytearray(128)

def _keccak_3x32(a: int, b: int, c: int) -> int:
    """keccak256(a||b||c) where a,b,c are 256-bit ints. Optimized hot path."""
    _BUF96[0:32] = a.to_bytes(32, "big")
    _BUF96[32:64] = b.to_bytes(32, "big")
    _BUF96[64:96] = c.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF96)
    return int.from_bytes(h.digest(), "big")

def _keccak_4x32(a: int, b: int, c: int, d: int) -> int:
    """keccak256(a||b||c||d) where a,b,c,d are 256-bit ints."""
    _BUF128[0:32] = a.to_bytes(32, "big")
    _BUF128[32:64] = b.to_bytes(32, "big")
    _BUF128[64:96] = c.to_bytes(32, "big")
    _BUF128[96:128] = d.to_bytes(32, "big")
    h = _keccak_mod.new(digest_bits=256)
    h.update(_BUF128)
    return int.from_bytes(h.digest(), "big")

# ============================================================
#  Tweakable Hash Primitives (matching TweakableHash.sol)
# ============================================================

def make_adrs(layer, tree, atype, kp, ci, cp, ha):
    """JARDIN 32-byte ADRS: layer(4) || tree(8) || type(4) || kp ci cp ha (4×4)."""
    return ((layer & 0xFFFFFFFF) << 224 |
            (tree & 0xFFFFFFFFFFFFFFFF) << 160 |
            (atype & 0xFFFFFFFF) << 128 |
            (kp & 0xFFFFFFFF) << 96 |
            (ci & 0xFFFFFFFF) << 64 |
            (cp & 0xFFFFFFFF) << 32 |
            (ha & 0xFFFFFFFF))

def make_adrs_fips(layer, tree, atype, kp, ci, cp, ha):
    """FIPS 205 §4.2 / §11.2.2 uncompressed 32-byte ADRS.

    Layout: layer(4) || tree(12) || type(4) || word1(4) || word2(4) || word3(4).
    Word assignments per type (FIPS 205 Table 1):
      0 WOTS_HASH  : w1=kp, w2=chain_address (=ci), w3=hash_address (=cp)
      1 WOTS_PK    : w1=kp, w2=0, w3=0
      2 TREE       : w1=0,  w2=tree_height   (=cp), w3=tree_index   (=ha)
      3 FORS_TREE  : w1=kp, w2=tree_height   (=cp), w3=tree_index   (=ha)
      4 FORS_ROOTS : w1=kp, w2=0, w3=0
    The (ci, cp, ha) JARDIN signature is preserved so call sites stay shared;
    this function maps to FIPS positions based on `atype`.
    """
    if atype == 0:
        w1, w2, w3 = kp, ci, cp        # ha unused — caller must pass 0
    elif atype == 1:
        w1, w2, w3 = kp, 0, 0
    elif atype == 2:
        w1, w2, w3 = 0, cp, ha          # ci/kp unused
    elif atype == 3:
        w1, w2, w3 = kp, cp, ha         # ci unused
    elif atype == 4:
        w1, w2, w3 = kp, 0, 0
    else:
        raise ValueError(f"unknown ADRS type {atype}")
    return ((layer & 0xFFFFFFFF) << 224 |
            (tree & 0xFFFFFFFFFFFFFFFFFFFFFFFF) << 128 |    # 96-bit tree
            (atype & 0xFFFFFFFF) << 96 |
            (w1 & 0xFFFFFFFF) << 64 |
            (w2 & 0xFFFFFFFF) << 32 |
            (w3 & 0xFFFFFFFF))

def th(seed, adrs, inp):
    return _keccak_3x32(seed, adrs, inp) & N_MASK

def th_pair(seed, adrs, left, right):
    return _keccak_4x32(seed, adrs, left, right) & N_MASK

def th_multi(seed, adrs, vals):
    data = to_b32(seed) + to_b32(adrs)
    for v in vals:
        data += to_b32(v)
    return keccak256(data) & N_MASK

HMSG_DOMAIN = (1 << 256) - 1  # 0xFFFF...FF — domain separator for H_msg

def h_msg(seed, root, R, message):
    """Domain-separated H_msg: keccak256(seed || root || R || message || domain).
    Hashes 160 bytes (5 words) vs 128 for ThPair/wotsDigest, ensuring
    unconditional domain separation via keccak's sponge construction."""
    data = to_b32(seed) + to_b32(root) + to_b32(R) + to_b32(message) + to_b32(HMSG_DOMAIN)
    return keccak256(data)

def chain_hash(seed, adrs, val, start_pos, steps):
    """JARDIN chain hash: hash_address packed into `cp` (bytes 24..28, shl 32)."""
    pos_clear = FULL ^ (0xFFFFFFFF << 32)
    for step in range(steps):
        pos = start_pos + step
        a = (adrs & pos_clear) | ((pos & 0xFFFFFFFF) << 32)
        val = _keccak_3x32(seed, a, val) & N_MASK
    return val

def chain_hash_fips(seed, adrs, val, start_pos, steps):
    """FIPS chain hash: hash_address is word3 (bytes 28..32, shl 0)."""
    pos_clear = FULL ^ 0xFFFFFFFF
    for step in range(steps):
        pos = start_pos + step
        a = (adrs & pos_clear) | (pos & 0xFFFFFFFF)
        val = _keccak_3x32(seed, a, val) & N_MASK
    return val

def set_chain_index(adrs, idx):
    """JARDIN: chain_index lives in `ci` (bytes 20..24, shl 64)."""
    mask = FULL ^ (0xFFFFFFFF << 64)
    return (adrs & mask) | ((idx & 0xFFFFFFFF) << 64)

def set_chain_index_fips(adrs, idx):
    """FIPS WOTS_HASH: chain_address is word2 (bytes 24..28, shl 32)."""
    mask = FULL ^ (0xFFFFFFFF << 32)
    return (adrs & mask) | ((idx & 0xFFFFFFFF) << 32)

def _adrs_helpers(cfg):
    """Return (make_adrs_fn, set_chain_index_fn, chain_hash_fn) for the variant."""
    if cfg is not None and cfg.get("adrs_mode") == "fips":
        return make_adrs_fips, set_chain_index_fips, chain_hash_fips
    return make_adrs, set_chain_index, chain_hash

# ============================================================
#  Key Derivation
# ============================================================

def derive_keys(message_int):
    entropy = keccak256(b"sphincs_signer_v1" + to_b32(message_int))
    seed = keccak256(b"pk_seed" + to_b32(entropy)) & N_MASK
    sk_seed = keccak256(b"sk_seed" + to_b32(entropy))
    return seed, sk_seed

def wots_secret(sk_seed, layer, tree, kp, chain_idx):
    data = (to_b32(sk_seed) + b"wots" +
            to_b4(layer) + to_b32(tree) + to_b4(kp) + to_b4(chain_idx))
    return keccak256(data) & N_MASK

def fors_secret(sk_seed, tree_idx, leaf_idx, ht_idx=None):
    """FORS leaf secret PRF.

    `ht_idx` binds the secret to the per-message hypertree leaf, so each leaf
    uses an independent FORS instance (standard SLH-DSA few-time-signature
    behaviour). Variants without the leaf binding pass ht_idx=None, keeping
    their original byte-for-byte preimage for layout compatibility."""
    data = to_b32(sk_seed) + b"fors"
    if ht_idx is not None:
        data += to_b4(ht_idx)
    data += to_b4(tree_idx) + to_b4(leaf_idx)
    return keccak256(data) & N_MASK

def pors_secret(sk_seed, sig_pos):
    data = to_b32(sk_seed) + b"pors" + to_b4(sig_pos)
    return keccak256(data) & N_MASK

# ============================================================
#  WOTS+C
# ============================================================

def _wots_params(cfg=None):
    """Return (w, log_w, l, len1, target_sum, w_mask) for a variant config."""
    if cfg and "w" in cfg:
        w = cfg["w"]
        return w, cfg["log_w"], cfg["l"], cfg["len1"], cfg["target_sum"], cfg["w_mask"]
    return W, LOG_W, L, LEN1, TARGET_SUM, W_MASK


def wots_keygen_pk_only(seed, sk_seed, layer, tree, kp, cfg=None):
    """Compute just the WOTS+C public key (no secret keys returned). Fast path for tree building."""
    w, _, l, _, _, _ = _wots_params(cfg)
    mk_adrs, set_ci, ch_hash = _adrs_helpers(cfg)
    base_adrs = mk_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    pk_elements = []
    for i in range(l):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        chain_adrs = set_ci(base_adrs, i)
        pk_i = ch_hash(seed, chain_adrs, sk_i, 0, w - 1)
        pk_elements.append(pk_i)
    pk_adrs = mk_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    return th_multi(seed, pk_adrs, pk_elements)

def wots_keygen(seed, sk_seed, layer, tree, kp, cfg=None):
    """Full keygen: returns (sk_list, wots_pk)."""
    w, _, l, _, _, _ = _wots_params(cfg)
    mk_adrs, set_ci, ch_hash = _adrs_helpers(cfg)
    base_adrs = mk_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    sk = []
    pk_elements = []
    for i in range(l):
        sk_i = wots_secret(sk_seed, layer, tree, kp, i)
        sk.append(sk_i)
        chain_adrs = set_ci(base_adrs, i)
        pk_i = ch_hash(seed, chain_adrs, sk_i, 0, w - 1)
        pk_elements.append(pk_i)
    pk_adrs = mk_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0)
    wots_pk = th_multi(seed, pk_adrs, pk_elements)
    return sk, wots_pk

def wots_digest(seed, layer, tree, kp, msg_hash, count, cfg=None):
    mk_adrs, _, _ = _adrs_helpers(cfg)
    hash_adrs = mk_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    return _keccak_4x32(seed, hash_adrs, msg_hash, count)

def extract_digits(d, cfg=None):
    _, log_w, _, len1, _, w_mask = _wots_params(cfg)
    return [(d >> (i * log_w)) & w_mask for i in range(len1)]

def wots_find_count(seed, layer, tree, kp, msg_hash, cfg=None):
    _, _, _, _, target_sum, _ = _wots_params(cfg)
    for count in range(10_000_000):
        d = wots_digest(seed, layer, tree, kp, msg_hash, count, cfg)
        digits = extract_digits(d, cfg)
        if sum(digits) == target_sum:
            return count, d, digits
    raise RuntimeError("WOTS+C count grinding failed")

def wots_sign(seed, sk, layer, tree, kp, msg_hash, cfg=None):
    w, _, l, _, _, _ = _wots_params(cfg)
    mk_adrs, set_ci, ch_hash = _adrs_helpers(cfg)
    count, d, digits = wots_find_count(seed, layer, tree, kp, msg_hash, cfg)
    base_adrs = mk_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0)
    sigma = []
    for i in range(l):
        chain_adrs = set_ci(base_adrs, i)
        sigma_i = ch_hash(seed, chain_adrs, sk[i], 0, digits[i])
        sigma.append(sigma_i)
    return sigma, count

# ============================================================
#  Merkle Trees
# ============================================================

def build_merkle_tree(seed, layer, tree, leaves, height, cfg=None):
    """Build Merkle tree. Returns list-of-lists: nodes[level][idx]."""
    mk_adrs, _, _ = _adrs_helpers(cfg)
    nodes = [list(leaves)]
    for h in range(height):
        prev = nodes[h]
        level = []
        for j in range(0, len(prev), 2):
            parent_idx = j // 2
            adrs = mk_adrs(layer, tree, ADRS_TREE, 0, 0, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[j], prev[j + 1]))
        nodes.append(level)
    return nodes

def get_auth_path(tree_nodes, leaf_idx, height):
    path = []
    idx = leaf_idx
    for h in range(height):
        path.append(tree_nodes[h][idx ^ 1])
        idx >>= 1
    return path

# ============================================================
#  Hypertree: Build subtree root (compute all 512 WOTS PKs)
# ============================================================

def build_subtree_root(seed, sk_seed, layer, tree, subtree_h, cfg=None):
    """Build a full subtree and return just the root. Computes all 2^subtree_h WOTS PKs."""
    n_leaves = 1 << subtree_h
    leaves = []
    for kp in range(n_leaves):
        pk = wots_keygen_pk_only(seed, sk_seed, layer, tree, kp, cfg)
        leaves.append(pk)
    nodes = build_merkle_tree(seed, layer, tree, leaves, subtree_h, cfg)
    return nodes[subtree_h][0]

def build_subtree_full(seed, sk_seed, layer, tree, subtree_h, cfg=None):
    """Build a full subtree with WOTS keypairs. Returns (wots_sks, tree_nodes, root)."""
    n_leaves = 1 << subtree_h
    wots_sks = []
    leaves = []
    for kp in range(n_leaves):
        sk, pk = wots_keygen(seed, sk_seed, layer, tree, kp, cfg)
        wots_sks.append(sk)
        leaves.append(pk)
    nodes = build_merkle_tree(seed, layer, tree, leaves, subtree_h, cfg)
    return wots_sks, nodes, nodes[subtree_h][0]

# ============================================================
#  FORS+C
# ============================================================

def build_fors_tree(seed, sk_seed, tree_idx, a, cfg=None, ht_idx=None, idx_leaf0=None, idx_tree0=None):
    """Build one FORS Merkle tree.

    When bound (ht_idx is not None — exact FIPS 205 FORS field split): tree
    address = idx_tree0, kp = idx_leaf0, tree_index = (tree_idx << (a-height))
    | node, tree_height = height, and the leaf secret PRF folds in ht_idx. This
    keys the FORS instance by the per-message hypertree leaf (matches C12 /
    SLH-DSA field semantics, FIPS 205 Alg. 17). Variants without the binding
    pass ht_idx=None: original layout (tree=0, kp=tree_idx, tree_index=node),
    secret PRF unchanged — byte-for-byte preserved."""
    mk_adrs, _, _ = _adrs_helpers(cfg)
    n_leaves = 1 << a
    leaves = []
    for j in range(n_leaves):
        secret = fors_secret(sk_seed, tree_idx, j, ht_idx)
        if ht_idx is not None:
            leaf_adrs = mk_adrs(0, idx_tree0, ADRS_FORS_TREE, idx_leaf0, 0, 0, (tree_idx << a) | j)
        else:
            leaf_adrs = mk_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, j)
        leaves.append(th(seed, leaf_adrs, secret))
    nodes = [leaves]
    for h in range(a):
        prev = nodes[h]
        level = []
        for idx in range(0, len(prev), 2):
            parent_idx = idx // 2
            if ht_idx is not None:
                ti = (tree_idx << (a - (h + 1))) | parent_idx
                adrs = mk_adrs(0, idx_tree0, ADRS_FORS_TREE, idx_leaf0, 0, h + 1, ti)
            else:
                adrs = mk_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, h + 1, parent_idx)
            level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
        nodes.append(level)
    return nodes, nodes[a][0]

def fors_sign_full(seed, sk_seed, digest, k, a, cfg=None):
    mk_adrs, _, _ = _adrs_helpers(cfg)
    a_mask = (1 << a) - 1
    indices = [(digest >> (i * a)) & a_mask for i in range(k)]
    assert indices[k - 1] == 0, f"Forced-zero violated: last index = {indices[k-1]}"

    # Exact FIPS 205 FORS field split: key the FORS instance by the per-message
    # hypertree leaf. htIdx = (digest >> k*a) & (2^h - 1) — the same value the
    # verifier parses and the hypertree consumes — split into the bottom subtree
    # (idx_tree0 → tree address) and leaf (idx_leaf0 → kp). Gated by cfg so
    # variants without the binding are byte-for-byte unchanged.
    ht_idx = idx_leaf0 = idx_tree0 = None
    if cfg and cfg.get("fors_bind_leaf"):
        ht_idx = (digest >> (k * a)) & ((1 << cfg["h"]) - 1)
        sh = cfg["subtree_h"]
        idx_leaf0 = ht_idx & ((1 << sh) - 1)
        idx_tree0 = ht_idx >> sh

    secrets = []
    auth_paths = []
    roots = []

    for t in range(k - 1):
        eprint(f"  FORS tree {t}/{k-1}...")
        tree_nodes, root = build_fors_tree(seed, sk_seed, t, a, cfg, ht_idx, idx_leaf0, idx_tree0)
        secrets.append(fors_secret(sk_seed, t, indices[t], ht_idx))
        auth_paths.append(get_auth_path(tree_nodes, indices[t], a))
        roots.append(root)

    eprint(f"  FORS tree {k-1}/{k-1} (forced-zero)...")
    _, root_last = build_fors_tree(seed, sk_seed, k - 1, a, cfg, ht_idx, idx_leaf0, idx_tree0)
    secrets.append(root_last)
    if ht_idx is not None:
        # Forced-zero tree (forsTree=k-1) as leaf node 0: tree_index = (k-1) << a
        fz_adrs = mk_adrs(0, idx_tree0, ADRS_FORS_TREE, idx_leaf0, 0, 0, (k - 1) << a)
        roots_adrs = mk_adrs(0, idx_tree0, ADRS_FORS_ROOTS, idx_leaf0, 0, 0, 0)
    else:
        fz_adrs = mk_adrs(0, 0, ADRS_FORS_TREE, k - 1, 0, 0, 0)
        roots_adrs = mk_adrs(0, 0, ADRS_FORS_ROOTS, 0, 0, 0, 0)
    roots.append(th(seed, fz_adrs, root_last))

    fors_pk = th_multi(seed, roots_adrs, roots)
    return secrets, auth_paths, fors_pk

# ============================================================
#  PORS+FP
# ============================================================

def extract_pors_indices(digest, k, tree_height):
    total_leaves = 1 << tree_height
    idx_mask = (1 << tree_height) - 1
    indices = []
    nonce = 0
    while len(indices) < k:
        ext = keccak256(to_b32(digest) + to_b32(nonce))
        b = 0
        while b + tree_height <= 256 and len(indices) < k:
            candidate = (ext >> b) & idx_mask
            b += tree_height
            if candidate < total_leaves and candidate not in indices:
                indices.append(candidate)
        nonce += 1
    # Insertion sort
    for i in range(1, len(indices)):
        key = indices[i]
        j = i
        while j > 0 and indices[j - 1] > key:
            indices[j] = indices[j - 1]
            j -= 1
        indices[j] = key
    return indices

def _extract_pors_unsorted(digest, k, tree_height):
    total_leaves = 1 << tree_height
    idx_mask = (1 << tree_height) - 1
    indices = []
    nonce = 0
    while len(indices) < k:
        ext = keccak256(to_b32(digest) + to_b32(nonce))
        b = 0
        while b + tree_height <= 256 and len(indices) < k:
            candidate = (ext >> b) & idx_mask
            b += tree_height
            if candidate < total_leaves and candidate not in indices:
                indices.append(candidate)
        nonce += 1
    return indices

def count_octopus_auth_nodes(sorted_indices, tree_height):
    current = list(sorted_indices)
    count = 0
    for level in range(tree_height):
        nxt = []
        j = 0
        while j < len(current):
            idx = current[j]
            sibling = idx ^ 1
            if j + 1 < len(current) and current[j + 1] == sibling:
                nxt.append(idx >> 1)
                j += 2
            else:
                count += 1
                nxt.append(idx >> 1)
                j += 1
        current = nxt
    return count

def compute_octopus_auth_set(tree_nodes, sorted_indices, tree_height):
    auth = []
    current = [(idx, tree_nodes[0][idx]) for idx in sorted_indices]
    for level in range(tree_height):
        nxt = []
        j = 0
        while j < len(current):
            idx, h_val = current[j]
            sibling = idx ^ 1
            parent = idx >> 1
            if j + 1 < len(current) and current[j + 1][0] == sibling:
                nxt.append((parent, tree_nodes[level + 1][parent]))
                j += 2
            else:
                auth.append(tree_nodes[level][sibling])
                nxt.append((parent, tree_nodes[level + 1][parent]))
                j += 1
        current = nxt
    return auth

# ============================================================
#  R Grinding
# ============================================================

# SECRET-KEYED randomizer (review C13-X-f2). R is bound to the secret sk_seed and
# the message: R = mask_n(keccak(sk_seed[32] || "R_grind" || message[32] ||
# nonce[32])), grinding nonce until the forced-zero / octopus predicate holds.
# Binding R to sk_seed removes public-grindability (an attacker can no longer
# offline-search (message, R) to steer the FORS index map / hypertree leaf onto
# previously-revealed instances), restoring the standard secret-randomizer
# few-time model, while staying deterministic per (key, message). The preimage
# layout MUST match signer-wasm/src/fors.rs::grind_r byte-for-byte or the
# Rust<->Python cross-check (and the on-chain digest) diverge. The verifier is
# unaffected — it only reads R out of the signature.
def grind_R_fors(seed, sk_seed, root, message, k, a):
    a_mask = (1 << a) - 1
    last_shift = (k - 1) * a
    for nonce in range(10_000_000):
        R = keccak256(to_b32(sk_seed) + b"R_grind" + to_b32(message) + to_b32(nonce)) & N_MASK
        digest = h_msg(seed, root, R, message)
        if (digest >> last_shift) & a_mask == 0:
            eprint(f"  R grind: found at nonce={nonce}")
            return R, digest
    raise RuntimeError("R grinding failed")

def grind_R_pors(seed, sk_seed, root, message, k, tree_height, m_max):
    for nonce in range(10_000_000):
        R = keccak256(to_b32(sk_seed) + b"R_grind" + to_b32(message) + to_b32(nonce)) & N_MASK
        digest = h_msg(seed, root, R, message)
        indices = extract_pors_indices(digest, k, tree_height)
        n = count_octopus_auth_nodes(indices, tree_height)
        if n <= m_max:
            eprint(f"  R grind: found at nonce={nonce}, auth_nodes={n}")
            return R, digest
    raise RuntimeError("R grinding failed")

# ============================================================
#  Utility
# ============================================================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# ============================================================
#  Full Signing
# ============================================================

def sign_variant(variant_name, message_int, seed=None, sk_seed=None, pk_root=None):
    cfg = VARIANTS[variant_name]
    d = cfg["d"]
    k = cfg["k"]
    a = cfg["a"]
    tree_height = cfg.get("tree_height", a)
    m_max = cfg["m_max"]
    subtree_h = cfg["subtree_h"]
    scheme = cfg["scheme"]
    h = cfg["h"]
    sig_size = cfg["sig_size"]

    if seed is None or sk_seed is None:
        seed, sk_seed = derive_keys(message_int)
    eprint(f"Signing {variant_name}: scheme={scheme}, h={h}, d={d}, k={k}, a={a}")
    eprint(f"  seed = {hex(seed)[:18]}...")

    if pk_root is None:
        if d == 2:
            pk_root = _build_hypertree_d2(seed, sk_seed, subtree_h, cfg)
        elif d == 3:
            pk_root = _build_hypertree_d3(seed, sk_seed, subtree_h, h, cfg)
        else:
            raise ValueError(f"Unsupported d={d}")

    eprint(f"  pkRoot = {hex(pk_root)[:18]}...")

    # ================================================================
    # STEP 2: Grind R
    # ================================================================
    if scheme == "fors":
        R, digest = grind_R_fors(seed, sk_seed, pk_root, message_int, k, a)
    else:
        R, digest = grind_R_pors(seed, sk_seed, pk_root, message_int, k, tree_height, m_max)

    # ================================================================
    # STEP 3: Decompose hypertree path
    # ================================================================
    ht_shift = k * a
    ht_mask = (1 << h) - 1
    htIdx = (digest >> ht_shift) & ht_mask

    path_info = []
    idx_tree = htIdx
    for lay in range(d):
        idx_leaf = idx_tree & ((1 << subtree_h) - 1)
        idx_tree_next = idx_tree >> subtree_h
        path_info.append((lay, idx_tree_next, idx_leaf))
        idx_tree = idx_tree_next

    eprint(f"  htIdx={htIdx}, path={path_info}")

    # ================================================================
    # STEP 4: Sign FORS/PORS
    # ================================================================
    if scheme == "fors":
        eprint("  Signing FORS+C...")
        fors_secrets, fors_auth_paths, bottom_pk = fors_sign_full(seed, sk_seed, digest, k, a, cfg)
    else:
        eprint("  Signing PORS+FP...")
        sorted_indices = extract_pors_indices(digest, k, tree_height)
        unsorted_indices = _extract_pors_unsorted(digest, k, tree_height)

        # Build PORS tree (single tree of height a)
        tree_pos_to_sig_pos = {}
        for sp, tp in enumerate(unsorted_indices):
            tree_pos_to_sig_pos[tp] = sp

        n_leaves = 1 << tree_height
        full_leaves = []
        for j in range(n_leaves):
            if j in tree_pos_to_sig_pos:
                sp = tree_pos_to_sig_pos[j]
                leaf_adrs = make_adrs(0, 0, ADRS_PORS, 0, 0, 0, j)
                secret = pors_secret(sk_seed, sp)
                leaf = th(seed, leaf_adrs, secret)
            else:
                leaf = keccak256(b"dummy_pors" + to_b32(sk_seed) + to_b4(j)) & N_MASK
            full_leaves.append(leaf)

        pors_tree_nodes = [full_leaves]
        for hh in range(tree_height):
            prev = pors_tree_nodes[hh]
            level = []
            for idx in range(0, len(prev), 2):
                parent_idx = idx // 2
                adrs = make_adrs(0, 0, ADRS_TREE, 0, 0, hh + 1, parent_idx)
                level.append(th_pair(seed, adrs, prev[idx], prev[idx + 1]))
            pors_tree_nodes.append(level)

        pors_auth_hashes = compute_octopus_auth_set(pors_tree_nodes, sorted_indices, tree_height)
        assert len(pors_auth_hashes) <= m_max, \
            f"Auth set {len(pors_auth_hashes)} > {m_max}"
        pors_secrets = [pors_secret(sk_seed, i) for i in range(k)]
        bottom_pk = pors_tree_nodes[tree_height][0]

    # ================================================================
    # STEP 5: Sign Hypertree
    # ================================================================
    eprint("  Signing hypertree...")
    ht_layers = []
    current_node = bottom_pk
    idx_tree = htIdx

    for lay in range(d):
        idx_leaf = idx_tree & ((1 << subtree_h) - 1)
        idx_tree = idx_tree >> subtree_h

        # Build the specific subtree to get WOTS secret keys and auth path
        eprint(f"    Building subtree layer={lay} tree={idx_tree}...")
        wots_sks, tree_nodes, _ = build_subtree_full(seed, sk_seed, lay, idx_tree, subtree_h, cfg)

        # Sign
        sigma, count = wots_sign(seed, wots_sks[idx_leaf], lay, idx_tree, idx_leaf, current_node, cfg)
        auth_path = get_auth_path(tree_nodes, idx_leaf, subtree_h)
        ht_layers.append((sigma, count, auth_path))

        # Verify internally: compute what verifier would get
        vw, _, vl, _, _, _ = _wots_params(cfg)
        mk_adrs, set_ci, ch_hash = _adrs_helpers(cfg)
        d_val = wots_digest(seed, lay, idx_tree, idx_leaf, current_node, count, cfg)
        digits = extract_digits(d_val, cfg)
        base_adrs = mk_adrs(lay, idx_tree, ADRS_WOTS, idx_leaf, 0, 0, 0)
        pk_elements = []
        for i in range(vl):
            ca = set_ci(base_adrs, i)
            pk_elements.append(ch_hash(seed, ca, sigma[i], digits[i], vw - 1 - digits[i]))
        pk_adrs = mk_adrs(lay, idx_tree, ADRS_WOTS_PK, idx_leaf, 0, 0, 0)
        wots_pk_v = th_multi(seed, pk_adrs, pk_elements)

        node = wots_pk_v
        m_idx = idx_leaf
        for hh in range(subtree_h):
            sib = auth_path[hh]
            pi = m_idx >> 1
            adrs = mk_adrs(lay, idx_tree, ADRS_TREE, 0, 0, hh + 1, pi)
            node = th_pair(seed, adrs, node, sib) if m_idx & 1 == 0 else th_pair(seed, adrs, sib, node)
            m_idx >>= 1
        current_node = node
        eprint(f"    Layer {lay}: root = {hex(current_node)[:18]}...")

    assert current_node == pk_root, \
        f"Root mismatch: {hex(current_node)} != {hex(pk_root)}"
    eprint("  Root verified!")

    # ================================================================
    # STEP 6: Pack Signature
    # ================================================================
    sig = b""
    sig += to_b32(R)[:N]

    if scheme == "fors":
        for s in fors_secrets:
            sig += to_b32(s)[:N]
        for path in fors_auth_paths:
            for node in path:
                sig += to_b32(node)[:N]
    else:
        for s in pors_secrets:
            sig += to_b32(s)[:N]
        for hv in pors_auth_hashes:
            sig += to_b32(hv)[:N]
        sig += b"\x00" * ((m_max - len(pors_auth_hashes)) * N)

    for sigma, count, auth_path in ht_layers:
        for s in sigma:
            sig += to_b32(s)[:N]
        sig += to_b4(count)
        for node in auth_path:
            sig += to_b32(node)[:N]

    assert len(sig) == sig_size, f"Sig size: {len(sig)} != {sig_size}"
    eprint(f"  Signature: {len(sig)} bytes")

    return seed, pk_root, sig


def sign_with_known_keys(variant_name, message_int, seed, sk_seed, pk_root):
    """Sign message_int with a pre-existing keypair (skips key derivation and pkRoot rebuild)."""
    _, _, sig = sign_variant(variant_name, message_int, seed=seed, sk_seed=sk_seed, pk_root=pk_root)
    return sig


# ============================================================
#  Hypertree Root Construction
# ============================================================

def _build_subtree_root_worker(args):
    """Worker for multiprocessing: compute one subtree root."""
    seed, sk_seed, layer, tree, subtree_h = args
    return build_subtree_root(seed, sk_seed, layer, tree, subtree_h)


def _build_hypertree_d2(seed, sk_seed, subtree_h, cfg=None):
    """Build pkRoot for d=2 hypertree.
    pkRoot = Merkle root of 2^subtree_h WOTS PKs at (layer=1, tree=0).
    Only needs 1 subtree computation."""
    eprint(f"  Computing pkRoot (1 subtree at top layer)...")
    t0 = time.time()
    pk_root = build_subtree_root(seed, sk_seed, 1, 0, subtree_h, cfg)
    eprint(f"  pkRoot done: {time.time()-t0:.1f}s")
    print("Public key is ",hex(pk_root))
    return pk_root


def _build_hypertree_d3(seed, sk_seed, subtree_h, h, cfg=None):
    """Build pkRoot for d=3 hypertree.
    pkRoot = Merkle root of 2^subtree_h WOTS PKs at (layer=2, tree=0).
    Only needs 1 subtree computation."""
    eprint(f"  Computing pkRoot (1 subtree at top layer=2)...")
    t0 = time.time()
    pk_root = build_subtree_root(seed, sk_seed, 2, 0, subtree_h, cfg)
    eprint(f"  pkRoot done: {time.time()-t0:.1f}s")
    return pk_root


# ============================================================
#  ABI Encoding & Main
# ============================================================

def abi_encode(seed, root, sig):
    encoded = b""
    encoded += to_b32(seed)
    encoded += to_b32(root)
    encoded += to_b32(0x60)  # offset to bytes
    encoded += to_b32(len(sig))
    padded_sig = sig + b"\x00" * ((32 - len(sig) % 32) % 32)
    encoded += padded_sig
    return encoded


def main():
    # if len(sys.argv) != 3:
    #     eprint(f"Usage: python3 signer.py <{'|'.join(VARIANTS)}> <0x_message_hex>")
    #     sys.exit(1)

    variant = sys.argv[1]
    # msg_hex = sys.argv[2]

    if variant not in VARIANTS:
        eprint(f"Unknown variant: {variant}. Available: {', '.join(VARIANTS)}.")
        sys.exit(1)
    
    private_key_hex = (
    "4c0883a69102937d6231471b5dbb6204"
    "fe5129617082795f8d8f6e6d9b6c7d1d"
    )

    private_key = PrivateKey(bytes.fromhex(private_key_hex))


    transaction = {
        "nonce": 0,
        "gasPrice": 20000000000,
        "gas": 22000,
        "to": "0x3535353535353535353535353535353535353535",
        "value": 1000000000000000,
        "data": b"",
        "chainId": 1
    }

    unsigned_tx = serializable_unsigned_transaction_from_dict(
        transaction
    )

    encoded = rlp.encode(unsigned_tx)

    msg_hex = keccak(encoded).hex()

    print("Transaction hash:")
    print(msg_hex)


    if msg_hex.startswith("0x"):
        msg_hex = msg_hex[2:]
    message_int = int(msg_hex, 16)

    t0 = time.time()
    seed, root, sig = sign_variant(variant, message_int)
    eprint(f"Total time: {time.time()-t0:.1f}s")

    print("Public seed is 0x",hex(seed))

    encoded = abi_encode(seed, root, sig)
    #print("0x" + encoded.hex())
    print("0x" + sig.hex())



if __name__ == "__main__":
    main()
