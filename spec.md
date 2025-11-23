# **Updated Flow for DFA + Chomsky and PDA with Host Aggregation**

## **I. Overview**

Two **connected but distinct parts**:

1. **DFA & Chomsky Grammar – Malicious Packet Detection**

   * Operates on **individual packet rows**.
   * Determines if **patterns of malicious packets** exist.
   * If **enough malicious packets come from a host (`id.orig_h`)**, that host can be blocked.

2. **PDA – Protocol Validation**

   * Operates on **aggregated sequences per host (`id.orig_h`)**.
   * Validates protocol correctness (e.g., TCP handshake sequences) using a **stack**.
   * Illustrates cases where **nested dependencies cannot be captured by DFA alone**.

---

## **II. Part 1 – DFA & Chomsky Grammar**

### **1. Input**

* Each row = **one packet**.
* Fields used as symbols: `proto`, `service`, `conn_state`, optionally `history`.
* Label: `label` (Malicious / Benign).

### **2. Data Flow**

1. **Parser** converts each row → `LabeledSequence` (sequence of symbols).
2. **PTA Construction**:

   * Builds prefix tree of sequences for **pattern detection**.
   * Nodes store counts of Malicious/Benign labels.
3. **DFA Conversion & Minimization**
4. **Chomsky Normal Form (CNF) Grammar Generation**

   * DFA states → nonterminals
   * Transitions → CNF productions using helper terminal nonterminals (Tn -> a)
   * Accepting states → optionally S -> ε (if DFA accepts empty string)
5. **Host-level decision**:

   * Aggregate packet-level classifications per `id.orig_h`.
   * If threshold of malicious sequences exceeded → **block host**.

---

## **III. Part 2 – PDA Protocol Validation**

### **1. Input**

* Aggregated **sequence of packets per host (`id.orig_h`)**.
* Only relevant symbols for protocol: `conn_state` (optionally `proto`).

### **2. Aggregation Rules**

* Group **all packets from same `id.orig_h`** in chronological order.
* Produce sequences like:

  ```
  host 192.168.100.103 → [S0, S0, S0, S1, SF, ...]
  ```
* Each sequence represents the host’s activity and will be **fed into the PDA**.

### **3. PDA Operation**

* States: `q0` (start), `q1` (mid), `qf` (accepting)
* Stack:

  * Push when connection starts (`S0`)
  * Pop when connection ends (`SF`)
* Acceptance: sequence ends with empty stack → protocol correctly followed.

### **4. Output**

* Validation result per host: accepted/rejected
* Optional stack trace for demonstration

---

## **IV. CLI / Pipeline Integration**

| Flag                        | Part | Description                                          |
| --------------------------- | ---- | ---------------------------------------------------- |
| `--export-grammar <file>`   | DFA  | Export Chomsky Normal Form (CNF) grammar            |
| `--classify`                | DFA  | Classify packet-level sequences                      |
| `--block-hosts`             | DFA  | Aggregate malicious packet detection per `id.orig_h` |
| `--pda-validate <seq-file>` | PDA  | Validate sequences aggregated by `id.orig_h`         |
| `--print-stack`             | PDA  | Print stack trace per sequence                       |

---

## **V. Key Notes**

1. **Distinct data usage**:

   * DFA: row-level sequences → detect malicious patterns → block host if needed.
   * PDA: aggregated per host → validate protocol sequencing → highlight DFA limitations.

2. **Integration**:

   * Both branches share **parsed symbols** but differ in **sequence aggregation and analysis granularity**.

3. **Visualization**:

   * DFA: minimized DFA diagram + production rules.
   * PDA: state diagram with stack transitions.

---

✅ **Summary Flow (Text)**

```
CSV packets (rows)
        │
        ├── Parser → LabeledSequence
        │
        ├── DFA/Chomsky branch (packet-level)
        │       ├─ PTA build
        │       ├─ DFA conversion & minimization
        │       ├─ Classify sequences
        │       ├─ Generate Type 3 production rules
        │       └─ Aggregate per host → block if threshold exceeded
        │
        └── PDA branch (aggregated by id.orig_h)
                ├─ Aggregate packets per host → sequence
                ├─ PDA simulation with stack
                └─ Validate protocol correctness → accepted/rejected
```
