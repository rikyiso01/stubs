from numpy import array, float32
from numpy.linalg import norm
from numpy.typing import NDArray
from subprocess import run, PIPE, check_call
from numpy.random import uniform
from os import environ
from argparse import ArgumentParser
from matplotlib.pyplot import plot, savefig, xlabel, ylabel, legend, title, xticks

RANGE = 1000

ACCEPTED_ERROR = 1e-5

SIZES = [3, 10, 100]
BLOCKS = [1, 10, 100]

PERF_SIZE = 1000
PERF_BLOCKS = [2**i for i in range(7)]

FLAGS = "-Wall -Wextra -Werror -fsanitize={} -g -pedantic-errors -pthread -std=gnu17"
ADDRESS_FLAGS = FLAGS.format("address")
THREAD_FLAGS = FLAGS.format("thread")


def create_matrix(n: int, m: int) -> NDArray[float]:
    return uniform(low=-RANGE, high=RANGE, size=(n, m)).astype(float32)


def print_matrix(m: NDArray[float]) -> str:
    return "\n".join(" ".join(map(str, row)) for row in m) + "\n"


def run_test(m: int, n: int, p: int, blocks: int) -> float:
    a = create_matrix(m, n)
    b = create_matrix(n, p)
    c = create_matrix(p, m)
    input = f"{blocks} {m} {n} {p}\n"
    input += print_matrix(a)
    input += print_matrix(b)
    input += print_matrix(c)
    output = run(
        ["./matrixmul"],
        input=input,
        stdout=PIPE,
        check=True,
        text=True,
    ).stdout
    output_lines = output.splitlines()[4:]
    actual = array(
        [
            [float(number) for number in line.strip().split()]
            for line in output_lines[:p]
        ]
    )
    time = float(output_lines[p].split()[-1])
    expected = c @ (a @ b)
    absolute_error = norm(expected - actual)
    relative_error = absolute_error / norm(expected)
    print(relative_error)
    assert relative_error < ACCEPTED_ERROR, relative_error
    return time


def run_tests():
    for m in SIZES:
        for n in SIZES:
            for p in SIZES:
                for block in BLOCKS:
                    print(f"{m=} {n=} {p=} {block=}")
                    print("Execution time:", run_test(m, n, p, block))


def compile(thread: bool) -> None:
    check_call(["make", "clean"])
    check_call(
        ["make"],
        env={"CFLAGS": THREAD_FLAGS if thread else ADDRESS_FLAGS} | environ,
    )


def test():
    compile(False)
    run_tests()
    compile(True)
    run_tests()


def performance():
    check_call(["make", "clean"])
    check_call(["make"])
    y: list[float] = []
    for block in PERF_BLOCKS:
        print(block, "blocks")
        y.append(run_test(PERF_SIZE, PERF_SIZE, PERF_SIZE, block))
    print(y)
    plot(PERF_BLOCKS, y, "-o", label="times")
    xlabel("threads")
    ylabel("times")
    title("performance")
    xticks(PERF_BLOCKS)
    legend()
    savefig("graph.png")


def main():
    parser = ArgumentParser()
    subparser = parser.add_subparsers(required=True, dest="action")
    subparser.add_parser("test")
    subparser.add_parser("perf")
    args = parser.parse_args()
    if args.action == "test":
        test()
    else:
        performance()


if __name__ == "__main__":
    main()
