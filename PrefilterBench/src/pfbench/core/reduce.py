"""Hash reduction strategies: 32-bit → N-bit address space mapping."""


def truncate(hash_value: int, bits: int) -> int:
    return hash_value & ((1 << bits) - 1)


def xor_fold_overlap(hash_value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    lo = hash_value & mask
    hi = (hash_value >> (32 - bits)) & mask
    return lo ^ hi


def xor_fold_kway(hash_value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    result = 0
    val = hash_value
    while val:
        result ^= val & mask
        val >>= bits
    return result


def xor_fold_16(hash_value: int, bits: int) -> int:
    if bits > 16:
        raise ValueError(f"xor_fold_16 supports at most 16 bits, got {bits}")
    folded = (hash_value & 0xFFFF) ^ ((hash_value >> 16) & 0xFFFF)
    return folded & ((1 << bits) - 1)
