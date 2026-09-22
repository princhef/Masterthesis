#!/usr/bin/env python3

"""
Generate realistic-looking unsigned EIP-1559 Ethereum transactions.

These transactions are NOT signed and are NOT broadcast.

For each transaction we calculate the actual Ethereum EIP-1559
signing hash:

    keccak256(
        0x02 || RLP([
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            destination,
            value,
            data,
            access_list
        ])
    )

Output:
    transactions.json

The resulting signing_hash values can be passed directly to the
SPHINCS- signer benchmark.
"""

import argparse
import json
import os
import random

from Crypto.Hash import keccak


CHAIN_ID = 11155111  # Sepolia


# ----------------------------------------------------------------------
# Ethereum Keccak-256
# ----------------------------------------------------------------------

def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# ----------------------------------------------------------------------
# Minimal RLP encoder
# ----------------------------------------------------------------------

def rlp_encode(item):
    """
    Minimal Ethereum RLP encoder supporting:
        bytes
        int
        lists
    """

    if isinstance(item, int):
        if item == 0:
            item = b""
        else:
            item = item.to_bytes(
                (item.bit_length() + 7) // 8,
                "big",
            )

    if isinstance(item, list):
        encoded = b"".join(rlp_encode(x) for x in item)

        if len(encoded) <= 55:
            return bytes([0xc0 + len(encoded)]) + encoded

        length = len(encoded)
        length_bytes = length.to_bytes(
            (length.bit_length() + 7) // 8,
            "big",
        )

        return (
            bytes([0xf7 + len(length_bytes)])
            + length_bytes
            + encoded
        )

    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item

        if len(item) <= 55:
            return bytes([0x80 + len(item)]) + item

        length = len(item)
        length_bytes = length.to_bytes(
            (length.bit_length() + 7) // 8,
            "big",
        )

        return (
            bytes([0xb7 + len(length_bytes)])
            + length_bytes
            + item
        )

    raise TypeError(f"Unsupported RLP type: {type(item)}")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def random_address(rng):
    return "0x" + rng.randbytes(20).hex()


def random_value_wei(rng):
    """
    Generate values roughly between:
        0.0001 ETH
        and
        0.1 ETH
    """

    min_value = 10**14
    max_value = 10**17

    return rng.randint(min_value, max_value)


def generate_data(rng):
    """
    Mostly normal ETH transfers have empty calldata.

    Occasionally generate small calldata to make the dataset
    more representative.
    """

    roll = rng.random()

    if roll < 0.80:
        return "0x"

    # 4-byte selector + a few random words.
    length = rng.choice([4, 36, 68, 100])

    return "0x" + rng.randbytes(length).hex()


# ----------------------------------------------------------------------
# EIP-1559 signing hash
# ----------------------------------------------------------------------

def eip1559_signing_hash(tx):
    """
    EIP-1559 transaction signing payload.

    Type-2 transaction:

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
    """

    to_bytes = bytes.fromhex(tx["to"][2:])

    data_bytes = bytes.fromhex(
        tx["data"][2:]
        if tx["data"].startswith("0x")
        else tx["data"]
    )

    # Empty access list.
    access_list = []

    payload = [
        tx["chain_id"],
        tx["nonce"],
        tx["max_priority_fee_per_gas"],
        tx["max_fee_per_gas"],
        tx["gas_limit"],
        to_bytes,
        tx["value"],
        data_bytes,
        access_list,
    ]

    encoded = rlp_encode(payload)

    # EIP-2718 typed transaction prefix.
    signing_payload = b"\x02" + encoded

    return keccak256(signing_payload)


# ----------------------------------------------------------------------
# Generate transactions
# ----------------------------------------------------------------------

def generate_transactions(count, seed):

    rng = random.Random(seed)

    transactions = []

    for nonce in range(count):

        # Typical-ish EIP-1559 fee values.
        priority_fee = rng.randint(
            1_000_000_000,
            3_000_000_000,
        )

        base_fee_estimate = rng.randint(
            10_000_000_000,
            40_000_000_000,
        )

        max_fee = (
            base_fee_estimate
            + priority_fee
            + rng.randint(
                5_000_000_000,
                30_000_000_000,
            )
        )

        data = generate_data(rng)

        # 21k for ordinary ETH transfers.
        # Higher if calldata exists.
        if data == "0x":
            gas_limit = 21_000
        else:
            gas_limit = rng.choice(
                [
                    30_000,
                    50_000,
                    75_000,
                    100_000,
                ]
            )

        tx = {
            "index": nonce,

            "type": 2,

            "chain_id": CHAIN_ID,

            "nonce": nonce,

            "max_priority_fee_per_gas": priority_fee,

            "max_fee_per_gas": max_fee,

            "gas_limit": gas_limit,

            "to": random_address(rng),

            "value": random_value_wei(rng),

            "data": data,

            "access_list": [],
        }

        signing_hash = eip1559_signing_hash(tx)

        tx["signing_hash"] = (
            "0x" + signing_hash.hex()
        )

        transactions.append(tx)

    return transactions


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of transactions",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=20260910,
        help="Deterministic RNG seed",
    )

    parser.add_argument(
        "--output",
        default="transactions.json",
        help="Output JSON file",
    )

    args = parser.parse_args()

    transactions = generate_transactions(
        args.count,
        args.seed,
    )

    with open(args.output, "w") as f:
        json.dump(
            {
                "description": (
                    "Unsigned EIP-1559 Ethereum "
                    "transactions for SPHINCS "
                    "signing benchmark"
                ),
                "chain_id": CHAIN_ID,
                "count": len(transactions),
                "transactions": transactions,
            },
            f,
            indent=2,
        )

    print(
        f"Generated {len(transactions)} transactions"
    )

    print(
        f"Network: Sepolia ({CHAIN_ID})"
    )

    print(
        f"Output: {args.output}"
    )

    print()

    for tx in transactions[:3]:
        print(
            f"#{tx['index']}: "
            f"nonce={tx['nonce']} "
            f"to={tx['to']} "
            f"value={tx['value']} "
            f"hash={tx['signing_hash']}"
        )


if __name__ == "__main__":
    main()
