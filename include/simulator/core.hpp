#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>

namespace automata_security {

struct GrammarDFA {
    std::vector<std::string> names; // index -> name
    std::unordered_map<std::string, std::size_t> idx;
    std::vector<std::unordered_map<std::string, std::size_t>> trans;
    std::vector<bool> accepting;
    std::size_t start{0};

    void add_state_if_missing(const std::string& name);
    void set_start(const std::string& name);
    void set_accepting(const std::string& name);
    void add_transition(const std::string& from, const std::string& on, const std::string& to);
    std::pair<bool, std::string> classify_with_reason(const std::vector<std::string>& seq) const;
};

bool load_cnf_grammar(const std::string& path, GrammarDFA& out, std::string& err);

struct PDAResult {
    bool ok{true};
    std::string reason;
};

PDAResult validate_pda_sequence(const std::vector<std::string>& seq);

// Helper for PDA trace
struct PDAStep {
    std::string op; // PUSH, POP, NO_OP
    std::string symbol;
    std::vector<std::string> stack_after;
    // Control state transition for visualizing PDA steps
    std::string current_state;
    std::string next_state;
};

struct PDATraceResult {
    bool ok{true};
    std::vector<PDAStep> steps;
};

PDATraceResult validate_pda_sequence_with_trace(const std::vector<std::string>& seq);

std::string trim(const std::string& s);
std::string unquote(const std::string& s);

} // namespace automata_security
