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

```bash
make
make run
```

Running without arguments loads the default IoT dataset at `datasets/iotMalware/CTU-IoT-Malware-Capture-1-1conn.log.labeled.csv`, splits it 70/30, trains the automaton, minimizes it, and prints evaluation metrics.

## Command Line Options

```text
--input=/path/to/file   Override IoT dataset path
--train-ratio=0.7       Train/test fraction (0 < ratio < 1)
--train-full            Train on entire dataset (skip split)
--test=/path/to/file    Additional IoT dataset to evaluate (repeatable)
--export-grammar=FILE  Write Chomsky Normal Form (CNF) grammar to FILE
```

Example:

```bash
./bin/automata_security --train-ratio=0.6 --test=datasets/iotMalware/CTU-IoT-Malware-Capture-3-1conn.log.labeled.csv
```

## Repository Layout

```
include/        Public headers for automata, parser, evaluator
src/            Module implementations and main entry point
datasets/       Sample IoT-23 CSV / log captures
Makefile        Build script producing bin/automata_security
```

## Next Steps

- Expand parsers to ingest the full IoT-23 dataset collection
- Add configuration-driven feature engineering for richer alphabets
- Integrate DOT-to-PNG rendering and automated reporting
- Compare capture-specific automata against combined training regimes
