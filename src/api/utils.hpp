#pragma once

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include "core.hpp"

// Helpers are declared inside the automata_security namespace to avoid
// name conflicts with types declared in `core.hpp`.
namespace automata_security {

// Helper to escape JSON strings
std::string json_escape(const std::string& s);

void print_error(const std::string& msg);

struct Grammar {
    std::map<std::string, std::string> terminals; // T0 -> proto=icmp
    std::map<std::string, std::vector<std::vector<std::string>>> productions; // S -> [[T0, A3], ...]
};

bool load_grammar_for_derivation(const std::string& path, Grammar& g);

// Load a DOT-formatted DFA into the provided GrammarDFA (declared in core.hpp)
// Returns true on success and sets `err` on failure.
bool load_dot_dfa(const std::string& path, GrammarDFA& out, std::string& err);

// PDA helper types and loader used by the PDA simulator
struct PDATransition {
    std::string input_symbol;   // input symbol or "ε"
    std::string pop_symbol;     // symbol to pop or "ε"
    std::vector<std::string> push_symbols;    // symbol(s) to push or empty if "ε"
    size_t next_state;
};

struct PDAState {
    std::string name;
    bool accepting = false;
    std::vector<PDATransition> transitions;
};

struct PDA {
    std::vector<PDAState> states;
    size_t start = 0;
    std::map<std::string, size_t> state_map;

    size_t get_or_add_state(const std::string& name);
};

// Load PDA DOT file into the PDA structure
bool load_dot_pda(const std::string& path, PDA& out, std::string& err);

} // namespace automata_security
