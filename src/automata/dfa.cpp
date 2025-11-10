#include "automata/dfa.hpp"

#include <algorithm>
#include <limits>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace automata_security {

DFA::DFA() : start_state_(0), sink_state_(std::numeric_limits<std::size_t>::max()) {}

DFA DFA::from_pta(const PTA& pta) {
    DFA dfa;
    const auto& pta_nodes = pta.nodes();
    dfa.states_.resize(pta_nodes.size());
    dfa.start_state_ = pta.start_state();

    std::unordered_set<std::string> alphabet_set;

    for (const auto& node : pta_nodes) {
        if (node.id >= dfa.states_.size()) {
            throw std::runtime_error("PTA node id out of bounds while constructing DFA.");
        }
        auto& state = dfa.states_[node.id];
        state.positive_count = node.positive_count;
        state.negative_count = node.negative_count;
        state.accepting = state.positive_count > state.negative_count;

        for (const auto& [symbol, target] : node.transitions) {
            state.transitions[symbol] = target;
            alphabet_set.insert(symbol);
        }
    }

    dfa.alphabet_.assign(alphabet_set.begin(), alphabet_set.end());
    std::sort(dfa.alphabet_.begin(), dfa.alphabet_.end());

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
        sink_state_ = states_.size();
        State sink;
        sink.accepting = false;
        sink.positive_count = 0;
        sink.negative_count = 1;
        for (const auto& symbol : alphabet_) {
            sink.transitions[symbol] = sink_state_;
        }
        states_.push_back(std::move(sink));

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
        const auto& state = states_[current];
        auto it = state.transitions.find(symbol);
        if (it == state.transitions.end()) {
            if (sink_state_ < states_.size()) {
                current = sink_state_;
            } else {
                return false;
            }
        } else {
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
        partitions.push_back({0});
        state_partition[0] = 0;
    }

    std::queue<std::pair<std::size_t, std::string>> work;
    for (std::size_t idx = 0; idx < partitions.size(); ++idx) {
        for (const auto& symbol : alphabet_) {
            work.emplace(idx, symbol);
        }
    }

    std::vector<char> involved_flag(n, 0);
    std::vector<std::size_t> touched;
    touched.reserve(n);

    while (!work.empty()) {
        auto [part_idx, symbol] = work.front();
        work.pop();

        // Mark states whose transition on symbol leads into partition part_idx
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

                for (const auto& sym : alphabet_) {
                    work.emplace(idx, sym);
                    work.emplace(new_index, sym);
                }
            }
        }

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

}  // namespace automata_security
