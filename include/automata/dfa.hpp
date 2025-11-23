#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "automata/pta.hpp"

namespace automata_security {

class DFA {
public:
    struct State {
        std::unordered_map<std::string, std::size_t> transitions;
        std::size_t positive_count{0};
        std::size_t negative_count{0};
        bool accepting{false};
    };

    DFA();

    static DFA from_pta(const PTA& pta);

    DFA minimize() const;

    bool classify(const std::vector<std::string>& sequence) const;

    std::string to_dot() const;

    const std::vector<State>& states() const { return states_; }
    std::size_t start_state() const { return start_state_; }
    const std::vector<std::string>& alphabet() const { return alphabet_; }
    std::string to_definition() const;
    // Generate a Chomsky Normal Form (CNF) grammar representation of this DFA.
    // The output will be a CNF grammar (A -> BC or A -> a) with additional
    // helper nonterminals T0..Tk mapping terminals to nonterminals (Tn -> a).
    // If the start state is accepting, an S -> ε production may be included.
    std::string to_chomsky() const;

private:
    std::vector<State> states_;
    std::size_t start_state_;
    std::vector<std::string> alphabet_;
    std::size_t sink_state_;

    void ensure_complete_transitions();
};

}  // namespace automata_security
