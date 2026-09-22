#!/usr/bin/env python3

"""
Benchmark SPHINCS signing of Ethereum EIP-1559 transaction signing hashes.

Input:
    transactions.json

Expected format:

{
    "chain_id": 11155111,
    "count": 100,
    "transactions": [
        {
            "index": 0,
            "type": 2,
            "chain_id": 11155111,
            "nonce": 0,
            "max_priority_fee_per_gas": 2000000000,
            "max_fee_per_gas": 35000000000,
            "gas_limit": 21000,
            "to": "0x...",
            "value": 123456789,
            "data": "0x",
            "access_list": [],
            "signing_hash": "0x..."
        }
    ]
}

The signing_hash is the REAL Ethereum EIP-1559 signing hash:

    keccak256(
        0x02 || RLP([
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list
        ])
    )

This benchmark DOES NOT:
    - generate transactions
    - broadcast transactions
    - perform ECDSA signing

It ONLY:
    1. Reads the Ethereum signing hash.
    2. Passes it to SPHINCS signer.py.
    3. Measures SPHINCS signing time.
    4. Stores the results.

Outputs:

    results.csv
        Per-transaction timing information.

    signatures.json
        Generated SPHINCS signatures and metadata.

"""

import argparse
import csv
import json
import statistics
import sys
import time

from pathlib import Path


# ----------------------------------------------------------------------
# Repository paths
# ----------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(
    0,
    str(REPO_ROOT / "script")
)

import signer


# ----------------------------------------------------------------------
# Load transactions
# ----------------------------------------------------------------------

def load_transactions(filename):

    with open(filename, "r") as f:
        dataset = json.load(f)

    if "transactions" not in dataset:
        raise ValueError(
            "Input JSON does not contain a 'transactions' array"
        )

    transactions = dataset["transactions"]

    if not isinstance(transactions, list):
        raise ValueError(
            "'transactions' must be a JSON array"
        )

    if len(transactions) == 0:
        raise ValueError(
            "No transactions found"
        )

    return dataset, transactions


# ----------------------------------------------------------------------
# Validate Ethereum signing hashes
# ----------------------------------------------------------------------

def get_message_hash(tx):

    if "signing_hash" not in tx:
        raise ValueError(
            f"Transaction {tx.get('index', '?')} "
            "does not contain signing_hash"
        )

    value = tx["signing_hash"]

    if not isinstance(value, str):
        raise ValueError(
            "signing_hash must be a hex string"
        )

    if value.startswith("0x"):
        value = value[2:]

    if len(value) != 64:
        raise ValueError(
            f"Transaction {tx.get('index', '?')} has an invalid "
            f"signing_hash length: {len(value)} hex characters"
        )

    try:
        message_bytes = bytes.fromhex(value)
    except ValueError:
        raise ValueError(
            f"Transaction {tx.get('index', '?')} "
            "contains an invalid signing_hash"
        )

    if len(message_bytes) != 32:
        raise ValueError(
            "Ethereum signing hash must be exactly 32 bytes"
        )

    message_int = int.from_bytes(
        message_bytes,
        byteorder="big"
    )

    return message_bytes, message_int


# ----------------------------------------------------------------------
# Build SPHINCS public key / hypertree
# ----------------------------------------------------------------------

def build_public_key(seed, sk_seed, variant):

    cfg = signer.VARIANTS[variant]

    if cfg["d"] == 2:

        return signer._build_hypertree_d2(
            seed,
            sk_seed,
            cfg["subtree_h"],
            cfg,
        )

    elif cfg["d"] == 3:

        return signer._build_hypertree_d3(
            seed,
            sk_seed,
            cfg["subtree_h"],
            cfg["h"],
            cfg,
        )

    else:

        raise ValueError(
            f"Unsupported SPHINCS d={cfg['d']}"
        )


# ----------------------------------------------------------------------
# Convert signature to bytes
# ----------------------------------------------------------------------

def signature_to_bytes(signature):

    if isinstance(signature, bytes):
        return signature

    if isinstance(signature, bytearray):
        return bytes(signature)

    if isinstance(signature, int):

        if signature == 0:
            return b"\x00"

        return signature.to_bytes(
            (signature.bit_length() + 7) // 8,
            byteorder="big",
        )

    raise TypeError(
        f"Unexpected signature type: {type(signature)}"
    )


# ----------------------------------------------------------------------
# Benchmark
# ----------------------------------------------------------------------

def benchmark(
    input_file,
    output_csv,
    output_signatures,
    variant,
    count,
    seed,
):

    # --------------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------------

    dataset, transactions = load_transactions(
        input_file
    )

    if count is not None:
        transactions = transactions[:count]

    if len(transactions) == 0:
        raise ValueError(
            "No transactions selected for benchmark"
        )

    print()
    print("=" * 70)
    print("SPHINCS Ethereum Transaction Signing Benchmark")
    print("=" * 70)

    print(
        f"Input:        {input_file}"
    )

    print(
        f"Variant:      {variant}"
    )

    print(
        f"Transactions: {len(transactions)}"
    )

    print(
        f"Chain ID:     {dataset.get('chain_id', 'unknown')}"
    )

    print()

    # --------------------------------------------------------------
    # Validate variant
    # --------------------------------------------------------------

    if variant not in signer.VARIANTS:
        available = ", ".join(
            signer.VARIANTS.keys()
        )

        raise ValueError(
            f"Unknown variant '{variant}'. "
            f"Available variants: {available}"
        )

    # --------------------------------------------------------------
    # Derive SPHINCS keys ONCE
    #
    # This is deliberately outside the per-transaction timer.
    #
    # Otherwise we'd measure:
    #
    #     key derivation + hypertree construction + signing
    #
    # for every transaction.
    #
    # Instead we measure:
    #
    #     signing only
    # --------------------------------------------------------------

    print("Initializing SPHINCS key...")

    keygen_start = time.perf_counter()

    derived = signer.derive_keys(seed)

    # signer.py returns:
    #
    #     seed, sk_seed
    #
    sphincs_seed = derived[0]
    sk_seed = derived[1]

    pk_root = build_public_key(
        sphincs_seed,
        sk_seed,
        variant,
    )

    keygen_elapsed = (
        time.perf_counter()
        - keygen_start
    )

    print(
        f"SPHINCS initialization: "
        f"{keygen_elapsed:.6f} seconds"
    )

    print()

    # --------------------------------------------------------------
    # Sign transactions
    # --------------------------------------------------------------

    results = []
    signatures = []

    for position, tx in enumerate(transactions):

        tx_index = tx.get(
            "index",
            position
        )

        message_bytes, message_int = (
            get_message_hash(tx)
        )

        print(
            f"[{position + 1:>4}/{len(transactions)}] "
            f"transaction={tx_index}"
        )

        print(
            f"      hash = "
            f"0x{message_bytes.hex()}"
        )

        # ----------------------------------------------------------
        # START TIMER
        #
        # Only the actual SPHINCS signing operation is timed.
        # ----------------------------------------------------------

        start = time.perf_counter()

        signature = signer.sign_variant(
            variant,
            message_int,
            seed=sphincs_seed,
            sk_seed=sk_seed,
            pk_root=pk_root,
        )

        elapsed = (
            time.perf_counter()
            - start
        )

        # ----------------------------------------------------------
        # END TIMER
        # ----------------------------------------------------------

        signature_bytes = signature_to_bytes(
            signature
        )

        result = {
            "index": tx_index,

            "nonce": tx.get(
                "nonce"
            ),

            "transaction_type": tx.get(
                "type"
            ),

            "chain_id": tx.get(
                "chain_id"
            ),

            "to": tx.get(
                "to"
            ),

            "value": tx.get(
                "value"
            ),

            "gas_limit": tx.get(
                "gas_limit"
            ),

            "message_hash":
                "0x" + message_bytes.hex(),

            "signature_bytes":
                len(signature_bytes),

            "sign_time_seconds":
                elapsed,

            "sign_time_ms":
                elapsed * 1000.0,
        }

        results.append(result)

        signatures.append(
            {
                "index": tx_index,

                "message_hash":
                    "0x" + message_bytes.hex(),

                "signature":
                    "0x" + signature_bytes.hex(),

                "signature_bytes":
                    len(signature_bytes),

                "sign_time_seconds":
                    elapsed,

                "sign_time_ms":
                    elapsed * 1000.0,
            }
        )

        print(
            f"      signature = "
            f"{len(signature_bytes)} bytes"
        )

        print(
            f"      time = "
            f"{elapsed:.6f} seconds "
            f"({elapsed * 1000.0:.3f} ms)"
        )

        print()

    # --------------------------------------------------------------
    # Timing statistics
    # --------------------------------------------------------------

    times = [
        r["sign_time_seconds"]
        for r in results
    ]

    total_time = sum(times)

    average_time = (
        total_time / len(times)
    )

    median_time = statistics.median(
        times
    )

    minimum_time = min(times)
    maximum_time = max(times)

    if len(times) >= 20:

        sorted_times = sorted(times)

        p95_index = int(
            0.95 * (len(sorted_times) - 1)
        )

        p95_time = sorted_times[
            p95_index
        ]

    else:

        p95_time = None

    throughput = (
        len(times) / total_time
    )

    # --------------------------------------------------------------
    # CSV
    # --------------------------------------------------------------

    with open(
        output_csv,
        "w",
        newline=""
    ) as f:

        fieldnames = [
            "index",
            "nonce",
            "transaction_type",
            "chain_id",
            "to",
            "value",
            "gas_limit",
            "message_hash",
            "signature_bytes",
            "sign_time_seconds",
            "sign_time_ms",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            results
        )

    # --------------------------------------------------------------
    # Signature JSON
    # --------------------------------------------------------------

    signature_output = {
        "variant": variant,

        "transaction_count":
            len(transactions),

        "chain_id":
            dataset.get(
                "chain_id"
            ),

        "key_initialization_seconds":
            keygen_elapsed,

        "seed":
            hex(sphincs_seed),

        "sk_seed":
            hex(sk_seed),

        "pk_root":
            hex(pk_root),

        "signatures":
            signatures,
    }

    with open(
        output_signatures,
        "w"
    ) as f:

        json.dump(
            signature_output,
            f,
            indent=2,
        )

    # --------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)

    print(
        f"Variant:                 {variant}"
    )

    print(
        f"Transactions signed:    {len(times)}"
    )

    print(
        f"Key initialization:      "
        f"{keygen_elapsed:.6f} s"
    )

    print(
        f"Total signing time:      "
        f"{total_time:.6f} s"
    )

    print(
        f"Average signing time:    "
        f"{average_time:.6f} s "
        f"({average_time * 1000:.3f} ms)"
    )

    print(
        f"Median signing time:     "
        f"{median_time:.6f} s "
        f"({median_time * 1000:.3f} ms)"
    )

    print(
        f"Minimum signing time:    "
        f"{minimum_time:.6f} s"
    )

    print(
        f"Maximum signing time:    "
        f"{maximum_time:.6f} s"
    )

    if p95_time is not None:

        print(
            f"P95 signing time:        "
            f"{p95_time:.6f} s "
            f"({p95_time * 1000:.3f} ms)"
        )

    print(
        f"Throughput:              "
        f"{throughput:.4f} signatures/sec"
    )

    print()

    print(
        f"Timing CSV:              "
        f"{output_csv}"
    )

    print(
        f"Signatures:              "
        f"{output_signatures}"
    )

    print("=" * 70)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Benchmark SPHINCS signing of "
            "Ethereum EIP-1559 transaction hashes."
        )
    )

    parser.add_argument(
        "--input",
        default="transactions.json",
        help=(
            "Input transaction dataset "
            "(default: transactions.json)"
        ),
    )

    parser.add_argument(
        "--output",
        default="results.csv",
        help=(
            "Timing CSV "
            "(default: results.csv)"
        ),
    )

    parser.add_argument(
        "--signatures",
        default="signatures.json",
        help=(
            "Signature JSON "
            "(default: signatures.json)"
        ),
    )

    parser.add_argument(
        "--variant",
        default="c13",
        help=(
            "SPHINCS variant "
            "(default: c13)"
        ),
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help=(
            "Only sign the first N transactions"
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help=(
            "SPHINCS deterministic seed "
            "(default: 1)"
        ),
    )

    args = parser.parse_args()

    benchmark(
        input_file=args.input,
        output_csv=args.output,
        output_signatures=args.signatures,
        variant=args.variant,
        count=args.count,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()

