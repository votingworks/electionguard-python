from math import sqrt
from timeit import default_timer as timer
from typing import Dict, List, NamedTuple, Tuple

from electionguard.chaum_pedersen import make_disjunctive_chaum_pedersen_zero
from electionguard.elgamal import (
    elgamal_keypair_from_secret,
    ElGamalKeyPair,
    elgamal_encrypt,
)
from electionguard.group import ElementModQ, int_to_q_unchecked, ONE_MOD_Q, rand_q
from electionguard.nonces import Nonces
from electionguard.utils import get_optional


class BenchInput(NamedTuple):
    keypair: ElGamalKeyPair
    r: ElementModQ
    s: ElementModQ


def chaum_pedersen_bench(bi: BenchInput) -> Tuple[float, float]:
    """
    Given an input (instance of the BenchInput tuple), constructs and validates
    a disjunctive Chaum-Pedersen proof, returning the time (in seconds) to do each operation.
    """
    (keypair, r, s) = bi
    ciphertext = get_optional(elgamal_encrypt(0, r, keypair.public_key))
    start1 = timer()
    proof = make_disjunctive_chaum_pedersen_zero(
        ciphertext, r, keypair.public_key, ONE_MOD_Q, s
    )
    end1 = timer()
    valid = proof.is_valid(ciphertext, keypair.public_key, ONE_MOD_Q)
    end2 = timer()
    if not valid:
        raise Exception("Wasn't expecting an invalid proof during a benchmark!")
    return end1 - start1, end2 - end1


def identity(x: int) -> int:
    """Placeholder function used just to warm up the parallel mapper prior to benchmarking."""
    return x


def average(l: List[float]) -> float:
    """Average of a list of numbers"""
    n = len(l)
    if n == 0:
        return 0
    return sum(l) / n


def std(l: List[float]) -> float:
    """Standard deviation of a list of numbers"""
    n = len(l)
    if n == 0:
        return 0
    avg = average(l)
    return sqrt(sum([(avg - i) * (avg - i) for i in l]))


if __name__ == "__main__":
    problem_sizes = (100, 500, 1000)
    rands = Nonces(int_to_q_unchecked(31337))
    speedup: Dict[int, float] = {}

    keypair = get_optional(elgamal_keypair_from_secret(rand_q()))

    # warm up the pool to help get consistent measurements
    bench_start = timer()

    for size in problem_sizes:
        print("(Unregistered Key) Benchmarking on problem size: ", size)
        inputs = [
            BenchInput(
                keypair,
                rands[size],
                rands[size + 1],
            )
            for _ in range(size)
        ]
        start_all_scalar = timer()
        timing_data = [chaum_pedersen_bench(i) for i in inputs]
        end_all_scalar = timer()

        print(f"  Creating Chaum-Pedersen proofs ({size} iterations)")
        avg_proof_scalar = average([t[0] for t in timing_data])
        std_proof_scalar = std([t[0] for t in timing_data])
        print(f"    Avg    = {avg_proof_scalar:.6f} sec")
        print(f"    Stddev = {std_proof_scalar:.6f} sec")

        print(f"  Validating Chaum-Pedersen proofs ({size} iterations)")
        avg_verify_scalar = average([t[1] for t in timing_data])
        std_verify_scalar = std([t[1] for t in timing_data])
        print(f"    Avg    = {avg_verify_scalar:.6f} sec")
        print(f"    Stddev = {std_verify_scalar:.6f} sec")

    keypair.public_key.accelerate_pow()
    for size in problem_sizes:
        print("(Registered Key) Benchmarking on problem size: ", size)
        inputs = [
            BenchInput(
                keypair,
                rands[size],
                rands[size + 1],
            )
            for _ in range(size)
        ]
        start_all_scalar = timer()
        timing_data = [chaum_pedersen_bench(i) for i in inputs]
        end_all_scalar = timer()

        print(f"  Creating Chaum-Pedersen proofs ({size} iterations)")
        avg_proof_scalar = average([t[0] for t in timing_data])
        std_proof_scalar = std([t[0] for t in timing_data])
        print(f"    Avg    = {avg_proof_scalar:.6f} sec")
        print(f"    Stddev = {std_proof_scalar:.6f} sec")

        print(f"  Validating Chaum-Pedersen proofs ({size} iterations)")
        avg_verify_scalar = average([t[1] for t in timing_data])
        std_verify_scalar = std([t[1] for t in timing_data])
        print(f"    Avg    = {avg_verify_scalar:.6f} sec")
        print(f"    Stddev = {std_verify_scalar:.6f} sec")
