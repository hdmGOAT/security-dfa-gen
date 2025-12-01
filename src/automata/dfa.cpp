#include "automata/dfa.hpp"

#include <algorithm>
#include <limits>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>
#include <cassert>

namespace automata_security {

DFA::DFA() : start_state_(0), sink_state_(std::numeric_limits<std::size_t>::max()) {}

DFA DFA::from_pta(const PTA& pta) {
    DFA dfa;
    const auto& pta_nodes = pta.nodes();
    // basic sanity: PTA must contain nodes
    assert(!pta_nodes.empty());
    dfa.states_.resize(pta_nodes.size());
    dfa.start_state_ = pta.start_state();
    // start state must be a valid index into states_
    assert(dfa.start_state_ < dfa.states_.size());

    std::unordered_set<std::string> alphabet_set;

    // Copy PTA nodes into DFA states. For each PTA node we:
    //  - propagate positive/negative example counts
    //  - set accepting flag by majority vote (positive_count > negative_count)
    //  - copy outgoing transitions and collect alphabet symbols
    for (const auto& node : pta_nodes) {
        if (node.id >= dfa.states_.size()) {
            throw std::runtime_error("PTA node id out of bounds while constructing DFA.");
        }
        auto& state = dfa.states_[node.id];

        // Transfer example counts and compute accepting/rejecting
        state.positive_count = node.positive_count;
        state.negative_count = node.negative_count;
        state.accepting = state.positive_count > state.negative_count;

        // Copy transitions from PTA node to DFA state. Also collect each
        // observed symbol into the alphabet set for later completion.
        for (const auto& [symbol, target] : node.transitions) {
            // ensure transition targets are within PTA node bounds
            if (target >= pta_nodes.size()) {
                throw std::runtime_error("PTA transition target out of bounds while constructing DFA.");
            }
            state.transitions[symbol] = target;
            alphabet_set.insert(symbol);
        }
    }

    // Move collected alphabet into the DFA and sort it for deterministic order
    dfa.alphabet_.assign(alphabet_set.begin(), alphabet_set.end());
    std::sort(dfa.alphabet_.begin(), dfa.alphabet_.end());

    // Ensure DFA has a defined transition for every state-symbol pair.
    // This may create a sink state if any transitions are missing.
    dfa.ensure_complete_transitions();
    return dfa;
}

void DFA::ensure_complete_transitions() {
    if (alphabet_.empty()) {
        sink_state_ = std::numeric_limits<std::size_t>::max();
        return;
    }

    bool needs_sink = false;
    for (const auto& state : states_) {
        for (const auto& symbol : alphabet_) {
            if (!state.transitions.count(symbol)) {
                needs_sink = true;
                break;
            }
        }
        if (needs_sink) {
            break;
        }
    }

    if (needs_sink) {
        // Create a sink (dead) state. This state is a catch-all target for any
        // missing transitions and is non-accepting. It also loops to itself on
        // every symbol so once reached no further progress occurs.
        sink_state_ = states_.size();
        State sink;
        sink.accepting = false;          // sink should not be accepting
        sink.positive_count = 0;
        sink.negative_count = 1;         // record as (pseudo) negative

        // Sink transitions: each symbol loops to the sink itself
        for (const auto& symbol : alphabet_) {
            sink.transitions[symbol] = sink_state_;
        }
        states_.push_back(std::move(sink));

        // Fill in any missing transitions in all states to point to the sink
        for (auto& state : states_) {
            for (const auto& symbol : alphabet_) {
                if (!state.transitions.count(symbol)) {
                    state.transitions[symbol] = sink_state_;
                }
            }
        }
    } else {
        sink_state_ = std::numeric_limits<std::size_t>::max();
    }
}

bool DFA::classify(const std::vector<std::string>& sequence) const {
    if (states_.empty()) {
        return false;
    }

    std::size_t current = start_state_;
    if (current >= states_.size()) {
        return false;
    }

    for (const auto& symbol : sequence) {
        // Advance the current state according to the symbol. If no explicit
        // transition exists and a sink was created, jump to the sink. If no
        // sink exists, classification fails (unknown symbol).
        const auto& state = states_[current];
        auto it = state.transitions.find(symbol);
        if (it == state.transitions.end()) {
            if (sink_state_ < states_.size()) {
                current = sink_state_;
            } else {
                // No transition and no sink: cannot classify further
                return false;
            }
        } else {
            // Follow the transition to the target state
            current = it->second;
        }
    }

    return states_[current].accepting;
}

DFA DFA::minimize() const {
    if (states_.empty()) {
        return *this;
    }

    std::size_t n = states_.size();
    // Hopcroft's minimization algorithm (partition refinement)
    // 1. Initialize partitions into accepting and rejecting states
    // 2. Use a work queue of (partition, symbol) to find states that transition
    //    into the partition on that symbol; split partitions based on this info
    //    until no more splits occur.
    std::vector<std::vector<std::size_t>> partitions;
    partitions.reserve(n);

    std::vector<std::size_t> accepting;
    std::vector<std::size_t> rejecting;
    accepting.reserve(n);
    rejecting.reserve(n);

    for (std::size_t i = 0; i < n; ++i) {
        if (states_[i].accepting) {
            accepting.push_back(i);
        } else {
            rejecting.push_back(i);
        }
    }

    std::vector<int> state_partition(n, -1);

    if (!accepting.empty()) {
        partitions.push_back(accepting);
        for (auto state : partitions.back()) {
            state_partition[state] = static_cast<int>(partitions.size() - 1);
        }
    }
    if (!rejecting.empty()) {
        partitions.push_back(rejecting);
        for (auto state : partitions.back()) {
            state_partition[state] = static_cast<int>(partitions.size() - 1);
        }
    }

    if (partitions.empty()) {
        // Degenerate case: no states? ensure at least one partition
        partitions.push_back({0});
        state_partition[0] = 0;
    }

    // Work queue contains pairs (partition_index, symbol) to examine
    std::queue<std::pair<std::size_t, std::string>> work;
    for (std::size_t idx = 0; idx < partitions.size(); ++idx) {
        for (const auto& symbol : alphabet_) {
            work.emplace(idx, symbol);
        }
    }

    // Temporary structures used during refinement
    std::vector<char> involved_flag(n, 0);
    std::vector<std::size_t> touched;
    touched.reserve(n);

    // Main refinement loop: while work queue not empty, use the (P, a) pair to
    // split partitions accordingly.
    while (!work.empty()) {
        auto [part_idx, symbol] = work.front();
        work.pop();

        // Find all states that on `symbol` transition into any state of partition
        // `part_idx`. We mark those 'involved' states (involved_flag) and
        // collect them in `touched` so we can later reset marks efficiently.
        // This identifies which states in each block will be separated by the
        // current refinement predicate.
        for (std::size_t s = 0; s < n; ++s) {
            auto it = states_[s].transitions.find(symbol);
            if (it != states_[s].transitions.end() &&
                state_partition[it->second] == static_cast<int>(part_idx)) {
                if (!involved_flag[s]) {
                    involved_flag[s] = 1;
                    touched.push_back(s);
                }
            }
        }

        // For each partition, split into subset (states that lead into `part_idx`)
        // and remainder (others). Replace original block with subset and append remainder
        // as a new partition when both are non-empty.
        // Examine each partition block and split it into two parts:
        //  - subset: states that have a transition on `symbol` into `part_idx`
        //  - remainder: the other states
        // If both vectors are non-empty, the block is refined (split). We
        // replace the original block with `subset` and append `remainder` as a
        // new partition. We also update `state_partition` for each affected state
        // so the partition mapping stays accurate.
        for (std::size_t idx = 0; idx < partitions.size(); ++idx) {
            auto& block = partitions[idx];
            std::vector<std::size_t> subset;
            std::vector<std::size_t> remainder;
            subset.reserve(block.size());
            remainder.reserve(block.size());

            for (auto state : block) {
                if (involved_flag[state]) {
                    subset.push_back(state);
                } else {
                    remainder.push_back(state);
                }
            }

            // If the block can be split into non-empty subset and remainder,
            // perform the partition update and re-enqueue refinement work for
            // both produced blocks across all symbols. This ensures further
            // cascading splits are discovered.
            if (!subset.empty() && !remainder.empty()) {
                block = std::move(subset);
                auto new_index = partitions.size();
                partitions.push_back(std::move(remainder));

                for (auto state : partitions[idx]) {
                    state_partition[state] = static_cast<int>(idx);
                }
                for (auto state : partitions[new_index]) {
                    state_partition[state] = static_cast<int>(new_index);
                }

                // Enqueue refinement tasks for both blocks for every alphabet
                // symbol. This drives further splitting until fixpoint.
                for (const auto& sym : alphabet_) {
                    work.emplace(idx, sym);
                    work.emplace(new_index, sym);
                }
            }
        }

        // Reset temporary marks
        for (auto state : touched) {
            involved_flag[state] = 0;
        }
        touched.clear();
    }

    DFA minimized;
    minimized.alphabet_ = alphabet_;
    minimized.states_.resize(partitions.size());
    minimized.start_state_ = partitions.empty()
                                 ? 0
                                 : static_cast<std::size_t>(state_partition[start_state_]);

    std::vector<std::size_t> representative(partitions.size(), 0);
    for (std::size_t idx = 0; idx < partitions.size(); ++idx) {
        if (!partitions[idx].empty()) {
            representative[idx] = partitions[idx].front();
        }
    }

    for (std::size_t idx = 0; idx < partitions.size(); ++idx) {
        const auto& block = partitions[idx];
        auto& new_state = minimized.states_[idx];
        new_state.positive_count = 0;
        new_state.negative_count = 0;

        for (auto state : block) {
            new_state.positive_count += states_[state].positive_count;
            new_state.negative_count += states_[state].negative_count;
        }
        new_state.accepting = new_state.positive_count > new_state.negative_count;

        const auto rep = representative[idx];
        for (const auto& [symbol, target] : states_[rep].transitions) {
            // Recreate transitions for the representative state's outgoing
            // edges. Targets are mapped to their partition index (new state id)
            // using the state_partition array so the minimized DFA transitions
            // refer to the compressed state space.
            new_state.transitions[symbol] =
                static_cast<std::size_t>(state_partition[target]);
        }
    }

    if (sink_state_ < states_.size()) {
        minimized.sink_state_ =
            static_cast<std::size_t>(state_partition[sink_state_]);
    } else {
        minimized.sink_state_ = std::numeric_limits<std::size_t>::max();
    }

    return minimized;
}

std::string DFA::to_dot() const {
    std::ostringstream out;
    out << "digraph DFA {\n";
    out << "  rankdir=LR;\n";
    out << "  node [shape=circle];\n";

    out << "  __start [shape=point];\n";
    out << "  __start -> s" << start_state_ << ";\n";

    for (std::size_t i = 0; i < states_.size(); ++i) {
        const auto& state = states_[i];
        out << "  s" << i << " [label=\"s" << i << "\\n+" << state.positive_count
            << " -" << state.negative_count << "\"";
        if (state.accepting) {
            out << ", shape=doublecircle";
        }
        if (sink_state_ == i) {
            out << ", style=dashed";
        }
        out << "];\n";
    }

    for (std::size_t i = 0; i < states_.size(); ++i) {
        for (const auto& [symbol, target] : states_[i].transitions) {
            out << "  s" << i << " -> s" << target << " [label=\"" << symbol
                << "\"];\n";
        }
    }

    out << "}\n";
    return out.str();
}

std::string DFA::to_definition() const {
    std::ostringstream out;
    out << "DFA Definition\n";
    out << "==============\n";

    out << "States (Q): {";
    for (std::size_t i = 0; i < states_.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << "s" << i;
    }
    out << "}\n";

    out << "Alphabet (Σ): {";
    for (std::size_t i = 0; i < alphabet_.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << alphabet_[i];
    }
    out << "}\n";

    out << "Start state (q0): s" << start_state_ << "\n";

    out << "Accepting states (F): {";
    bool first_accepting = true;
    for (std::size_t i = 0; i < states_.size(); ++i) {
        if (states_[i].accepting) {
            if (!first_accepting) {
                out << ", ";
            }
            out << "s" << i;
            first_accepting = false;
        }
    }
    if (first_accepting) {
        out << "∅";
    }
    out << "}\n";

    if (sink_state_ < states_.size()) {
        out << "Sink state: s" << sink_state_ << "\n";
    }

    out << "Transitions (δ):\n";
    for (std::size_t i = 0; i < states_.size(); ++i) {
        std::vector<std::pair<std::string, std::size_t>> transitions(states_[i].transitions.begin(),
                                                                     states_[i].transitions.end());
        std::sort(transitions.begin(), transitions.end(),
                  [](const auto& lhs, const auto& rhs) {
                      if (lhs.first == rhs.first) {
                          return lhs.second < rhs.second;
                      }
                      return lhs.first < rhs.first;
                  });
        for (const auto& [symbol, target] : transitions) {
            out << "  δ(s" << i << ", " << symbol << ") = s" << target << "\n";
        }
    }

    return out.str();
}

std::string DFA::to_chomsky() const {
    std::ostringstream out;
    out << "# Chomsky Normal Form (CNF) grammar generated from DFA\n";

    // helper to quote terminals that contain spaces or special chars
    auto quote = [](const std::string& s) -> std::string {
        if (s.empty()) return "\"\"";
        bool need = false;
        for (char c : s) {
            if (c == ' ' || c == '"' || c == '\\') { need = true; break; }
        }
        if (!need) return s;
        std::string esc;
        esc.reserve(s.size());
        for (char c : s) {
            if (c == '"' || c == '\\') esc.push_back('\\');
            esc.push_back(c);
        }
        return std::string("\"") + esc + "\"";
    };

    // list terminals (quoted when needed)
    out << "Terminals: {";
    for (std::size_t i = 0; i < alphabet_.size(); ++i) {
        if (i != 0) out << ", ";
        out << quote(alphabet_[i]);
    }
    out << "}\n";

    // nonterminals corresponding to DFA states; use 'S' as the start nonterminal
    // and assign remaining nonterminals A0, A1, ... sequentially (no gaps)
    std::vector<std::string> state_names(states_.size());
    // place S for start
    if (start_state_ < state_names.size()) {
        state_names[start_state_] = "S";
    }
    // assign A0.. in order for other states
    std::size_t a_idx = 0;
    for (std::size_t i = 0; i < states_.size(); ++i) {
        if (i == start_state_) continue;
        state_names[i] = std::string("A") + std::to_string(a_idx++);
    }

    // print nonterminals with S first then the A# names in order
    out << "Nonterminals: {";
    out << "S";
    for (std::size_t i = 0; i < states_.size(); ++i) {
        if (i == start_state_) continue;
        out << ", " << state_names[i];
    }
    out << "}\n";

    out << "Start: S\n";

    // We'll create helper nonterminals T0..Tk mapping to terminals
    std::unordered_map<std::string, std::string> term_to_T;
    term_to_T.reserve(alphabet_.size());
    for (std::size_t i = 0; i < alphabet_.size(); ++i) {
        term_to_T[alphabet_[i]] = "T" + std::to_string(i);
    }

    out << "Productions:\n";

    // Emit terminal nonterminal mappings first: Tn -> terminal (quoted as needed)
    for (std::size_t i = 0; i < alphabet_.size(); ++i) {
        out << "  T" << i << " -> " << quote(alphabet_[i]) << "\n";
    }

    // For each DFA-state nonterminal A_i produce CNF productions
    // A -> a  (if transition to accepting state)
    // A -> T_a B  (for transitions on 'a' to state B)
    auto name_for_state = [&](std::size_t idx) -> std::string {
        if (idx < state_names.size()) return state_names[idx];
        return std::string("A") + std::to_string(idx);
    };

    for (std::size_t i = 0; i < states_.size(); ++i) {
        const auto& st = states_[i];
        // collect unique CNF alternatives (to avoid duplicates)
        std::set<std::string> opts;

        for (const auto& [symbol, target] : st.transitions) {
            auto it = term_to_T.find(symbol);
            if (it == term_to_T.end()) continue; // shouldn't happen
            const std::string& Tname = it->second;

            // A_i -> T_symbol A_target  (two nonterminals)
            std::ostringstream two;
            two << Tname << " " << name_for_state(target);
            // Add a binary production which uses a helper terminal nonterminal
            // (T_symbol) followed by the nonterminal for the target state. This
            // ensures resulting grammar is in CNF (A -> TB form).
            opts.insert(two.str());

            // If the target is accepting, keep A_i -> terminal as CNF terminal production
            // If the transition leads to an accepting state, we also include a
            // direct terminal alternative (A -> terminal) so that sentences
            // that end here can terminate in CNF via the helper terminal
            // production Tn -> terminal emitted above.
            if (target < states_.size() && states_[target].accepting) {
                std::ostringstream termprod;
                termprod << quote(symbol);
                opts.insert(termprod.str());
            }
        }

        // If start state accepts empty string, include epsilon as special-case
        if (start_state_ < states_.size() && states_[start_state_].accepting && i == start_state_) {
            opts.insert(std::string("ε"));
        }

        if (opts.empty()) continue;

        out << "  " << name_for_state(i) << " -> ";
        bool first = true;
        for (const auto& o : opts) {
            if (!first) out << " | ";
            out << o;
            first = false;
        }
        out << "\n";
    }

    return out.str();
}

}  // namespace automata_security
