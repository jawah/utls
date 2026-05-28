from __future__ import annotations

import os

import nox


def tests_impl(
    session: nox.Session,
    tracemalloc_enable: bool = False,
) -> None:
    # Install deps and the package itself (BoringSSL build via maturin).
    session.install("-U", "pip", "maturin", silent=False)
    session.install(".[test]", silent=False)

    # Show the pip version.
    session.run("pip", "--version")
    # Print the Python version and bytesize.
    session.run("python", "--version")
    session.run("python", "-c", "import struct; print(struct.calcsize('P') * 8)")

    session.run(
        "python",
        "-m",
        *(
            (
                "coverage",
                "run",
                "--parallel-mode",
                "-m",
            )
            if tracemalloc_enable is False
            else ()
        ),
        "pytest",
        "-v",
        "-ra",
        f"--color={'yes' if 'GITHUB_ACTIONS' in os.environ else 'auto'}",
        "--tb=native",
        "--durations=10",
        "--strict-config",
        "--strict-markers",
        *(session.posargs or ("tests/",)),
        env={
            "PYTHONWARNINGS": "always::DeprecationWarning",
            "COVERAGE_CORE": "sysmon",
            "PYTHONTRACEMALLOC": "25" if tracemalloc_enable else "",
        },
    )


@nox.session(
    python=[
        "3.7",
        "3.8",
        "3.9",
        "3.10",
        "3.11",
        "3.12",
        "3.13",
        "3.14",
        "3.13t",
        "3.14t",
    ]
)
def test(session: nox.Session) -> None:
    tests_impl(session)


@nox.session(python=["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"])
def tracemalloc(session: nox.Session) -> None:
    tests_impl(session, tracemalloc_enable=True)


@nox.session()
def format(session: nox.Session) -> None:
    """Run code formatters."""
    lint(session)


@nox.session
def lint(session: nox.Session) -> None:
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")
