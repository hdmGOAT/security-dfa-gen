# Automata Security Toolkit

Deterministic finite automata (DFA) pipeline for IoT intrusion detection using real-world network connection traces. The project builds Prefix Tree Acceptors (PTAs) from labeled sequences, minimizes them via Hopcroft's algorithm, and evaluates their classification performance.

## Features

- CSV log parser for IoT-23 connection records (pipe-delimited Zeek logs)
- PTA construction over symbolic sequences with positive/negative labels
- DFA minimization with complete transition handling and optional DOT export
- Train/test evaluation pipeline with accuracy, FPR, and FNR metrics
- Holdout testing across multiple IoT captures from the same alphabet
- Exportable DFA visuals (DOT) and formal definitions for inspection
- Modular C++17 implementation built with a simple Makefile

## Prerequisites

- GCC/Clang with C++17 support
- GNU Make
- (Optional) Graphviz for rendering DOT exports

Datasets should be placed under the `datasets/` directory. Defaults match the sample files included in this workspace.

## Build & Run

Build the primary tools (`api` and `generator`):

```bash
make
```

This produces `bin/api` (or `bin/api.exe` on Windows when using the `windows` target) and `bin/generator`.

Windows notes

- The provided `Makefile` and build steps assume a Unix-like environment. On Windows you can either:
	- Use WSL (recommended) and run `make` inside the WSL shell, or
	- Use MSYS2 / MinGW or a Visual Studio toolchain to build the project and produce a Windows binary (e.g., `bin/api.exe`).

If you build a native Windows binary, put it in `bin/` as `api.exe` so other components (backend) can locate and execute it.

Running without arguments (where applicable) uses the default IoT dataset at `datasets/iotMalware/CTU-IoT-Malware-Capture-1-1conn.log.labeled.csv` for operations that accept datasets.

Note: the standalone `simulator` CLI was removed — its core logic now lives in `include/core.hpp` and `src/core/simulator_core.cpp` and is used by the `api` program. If you need a separate simulator CLI again, reintroduce a `main` that links against the core code.

## Command Line Options

```text
--input=/path/to/file   Override IoT dataset path
--train-ratio=0.7       Train/test fraction (0 < ratio < 1)
--train-full            Train on entire dataset (skip split)
--test=/path/to/file    Additional IoT dataset to evaluate (repeatable)
--export-grammar=FILE  Write Chomsky Normal Form (CNF) grammar to FILE
```

Examples:

Run the API CLI (shows usage/help):

```bash
./bin/api --help
```

Run the generator tool (if applicable):

```bash
./bin/generator --help
```

## Repository Layout

```
include/        Public headers for automata, parser, evaluator
src/            Module implementations; core simulation logic under `src/core`
bin/            Build outputs (api, generator)
datasets/       Sample IoT-23 CSV / log captures
Makefile        Build script
```

## Next Steps

- Expand parsers to ingest the full IoT-23 dataset collection
- Add configuration-driven feature engineering for richer alphabets
- Integrate DOT-to-PNG rendering and automated reporting
- Compare capture-specific automata against combined training regimes
