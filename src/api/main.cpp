#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <regex>
#include <map>
#include <deque>
#include <set>

#include "core.hpp"
#include "utils.hpp"

using namespace automata_security;

// build_derivation_steps:
// This function figures out the step-by-step "story" of how the grammar produces a specific sequence of inputs.
// It starts with the start symbol 'S' and tries to find rules that match the input symbols one by one.
static std::vector<std::string> build_derivation_steps(const Grammar& g, const std::vector<std::string>& seq) {
    std::vector<std::string> derivation;
    derivation.push_back("S"); // Start with the initial symbol.

    std::string processed_prefix; // The part of the input we have already matched.
    std::string current_nt = "S"; // The current non-terminal symbol we are trying to expand.

    // Helper: Adds a line to the derivation history.
    // It combines the already matched part (processed_prefix) with the current rule's right-hand side (rhs).
    auto emit_rhs = [&](const std::vector<std::string>& prod, bool translate_terminals) {
        std::string rhs;
        for (size_t i = 0; i < prod.size(); ++i) {
            if (i > 0) rhs += " ";
            const auto& token = prod[i];
            // If it's a terminal placeholder (like T_0), look up its real value (like "tcp").
            if (translate_terminals && !token.empty() && token[0] == 'T' && g.terminals.count(token)) {
                rhs += g.terminals.at(token);
            } else {
                rhs += token;
            }
        }
        std::string line = processed_prefix + rhs;
        // Only add if it's different from the last line (avoid duplicates).
        if (derivation.back() != line) {
            derivation.push_back(line);
        }
    };

    // Helper: Records the application of a production rule.
    // Sometimes we show the raw rule (with T_0) first, then the translated one (with "tcp").
    auto append_production_steps = [&](const std::vector<std::string>& prod) {
        bool needs_raw_step = !prod.empty() && !prod[0].empty() && prod[0][0] == 'T' && g.terminals.count(prod[0]);
        if (needs_raw_step) emit_rhs(prod, false);
        emit_rhs(prod, true);
    };

    // Helper: Tries to move forward in the grammar without consuming any input.
    // This handles "unit productions" (A -> B) or "epsilon productions" (A -> ε).
    auto advance_without_consuming = [&](bool allow_all_epsilon) {
        bool expanded = false;
        std::set<std::string> seen;
        // Keep expanding as long as we have a current non-terminal.
        while (!current_nt.empty()) {
            if (seen.count(current_nt)) break; // Avoid infinite loops.
            seen.insert(current_nt);

            auto it = g.productions.find(current_nt);
            if (it == g.productions.end()) break;

            bool progressed = false;
            for (const auto& prod : it->second) {
                if (prod.empty()) continue;

                // Case 1: Unit production (e.g., A -> B).
                bool unit_nt = (prod.size() == 1 && g.productions.count(prod[0]));
                if (unit_nt) {
                    append_production_steps(prod);
                    current_nt = prod[0]; // Move to the next non-terminal.
                    progressed = expanded = true;
                    break;
                }

                // Skip over epsilons (ε).
                size_t idx = 0;
                while (idx < prod.size() && prod[idx] == "ε") idx++;

                // Case 2: Production starts with ε then a non-terminal (e.g., A -> ε B).
                if (idx < prod.size() && g.productions.count(prod[idx])) {
                    append_production_steps(prod);
                    current_nt = prod[idx];
                    progressed = expanded = true;
                    break;
                }

                // Case 3: All epsilon (e.g., A -> ε).
                // Only allowed if we are explicitly looking for it (usually at the end).
                if (allow_all_epsilon) {
                    bool all_eps = true;
                    for (const auto& token : prod) {
                        if (token != "ε") {
                            all_eps = false;
                            break;
                        }
                    }
                    if (all_eps) {
                        append_production_steps(prod);
                        progressed = expanded = true;
                        current_nt.clear(); // Nothing left to expand.
                        break;
                    }
                }
            }

            if (!progressed) break;
        }
        return expanded;
    };

    // Initial expansion (handle start rules like S -> A).
    advance_without_consuming(false);

    // Loop through each symbol in the input sequence.
    for (size_t seq_idx = 0; seq_idx < seq.size(); ++seq_idx) {
        const auto& sym = seq[seq_idx];
        bool is_last = (seq_idx == seq.size() - 1);

        // Try to advance non-consuming rules again before processing the symbol.
        advance_without_consuming(false);

        auto prod_it = g.productions.find(current_nt);
        if (prod_it == g.productions.end()) break;

        struct Candidate {
            const std::vector<std::string>* prod;
            std::string next_nt;
        };

        // Find all production rules that could match the current symbol.
        std::vector<Candidate> candidates;
        for (const auto& prod : prod_it->second) {
            if (prod.empty()) continue;

            size_t idx = 0;
            while (idx < prod.size() && prod[idx] == "ε") idx++;
            if (idx >= prod.size()) continue;

            const auto& token = prod[idx];
            bool match = false;
            std::string terminal_value;

            // Check if the token matches the input symbol.
            if (!token.empty() && token[0] == 'T' && g.terminals.count(token)) {
                terminal_value = g.terminals.at(token);
                match = (terminal_value == sym);
            } else if (!g.productions.count(token)) {
                terminal_value = token;
                match = (terminal_value == sym);
            } else {
                // It's a non-terminal, so this rule doesn't start with a terminal. Skip.
                continue;
            }

            if (!match) continue;

            // Find the next non-terminal in this rule to continue the chain.
            std::string next_nt;
            for (size_t j = idx + 1; j < prod.size(); ++j) {
                if (prod[j] == "ε") continue;
                if (g.productions.count(prod[j])) {
                    next_nt = prod[j];
                    break;
                }
            }

            candidates.push_back({&prod, next_nt});
        }

        // Select the best candidate rule.
        const std::vector<std::string>* selected_prod = nullptr;
        std::string selected_next_nt;
        for (const auto& cand : candidates) {
            // Heuristic: If it's the last symbol, prefer rules that finish (no next_nt).
            // Otherwise, prefer rules that continue (have a next_nt).
            if (is_last) {
                if (cand.next_nt.empty()) {
                    selected_prod = cand.prod;
                    selected_next_nt = cand.next_nt;
                    break;
                }
            } else {
                if (!cand.next_nt.empty()) {
                    selected_prod = cand.prod;
                    selected_next_nt = cand.next_nt;
                    break;
                }
            }
        }

        // Fallback: just pick the first one if no heuristic match.
        if (!selected_prod && !candidates.empty()) {
            selected_prod = candidates[0].prod;
            selected_next_nt = candidates[0].next_nt;
        }

        if (!selected_prod) break; // No matching rule found.

        // Apply the selected rule.
        const auto& prod = *selected_prod;
        append_production_steps(prod);

        // Update state for the next iteration.
        processed_prefix += sym + " ";
        current_nt = selected_next_nt;
        advance_without_consuming(false);
    }

    // Final cleanup: expand any remaining epsilon rules.
    advance_without_consuming(true);

    return derivation;
}

// build_pda_grammar_rules:
// This function takes a PDA (Pushdown Automaton) and converts its logic into a set of grammar rules.
// This is useful for visualizing the PDA's behavior as if it were a simple grammar.
static std::vector<std::string> build_pda_grammar_rules(const PDA& pda, const std::string& source_label) {
    std::vector<std::string> rules;
    rules.push_back("# PDA grammar (control-state CFG) derived from: " + source_label);
    
    // Identify the start state.
    std::string start_symbol;
    if (!pda.states.empty() && pda.start < pda.states.size()) {
        start_symbol = pda.states[pda.start].name;
        rules.push_back("Start state: " + start_symbol);
    }

    // Identify all accepting (valid final) states.
    std::vector<std::string> accepting;
    for (const auto& st : pda.states) {
        if (st.accepting) accepting.push_back(st.name);
    }
    if (!accepting.empty()) {
        std::string line = "Accepting states: ";
        for (size_t i = 0; i < accepting.size(); ++i) {
            if (i > 0) line += ", ";
            line += accepting[i];
        }
        rules.push_back(line);
    }

    // Helper: Formats a symbol for display (handles empty symbols as epsilon).
    auto fmt_symbol = [](const std::string& sym) {
        if (sym.empty() || sym == "ε") return std::string("ε");
        return sym;
    };

    // Store productions (rules) in a map to group them by the left-hand side (LHS).
    std::map<std::string, std::set<std::string>> productions;
    auto add_prod = [&productions](const std::string& lhs, const std::string& rhs) {
        if (lhs.empty() || rhs.empty()) return;
        productions[lhs].insert(rhs);
    };

    // Add the initial rule: S -> StartState.
    if (!start_symbol.empty()) {
        add_prod("S", start_symbol);
    }

    // Iterate through all states in the PDA to build rules.
    for (const auto& st : pda.states) {
        // If a state is accepting and has no transitions, it can transition to epsilon (finish).
        if (st.transitions.empty() && st.accepting) {
            add_prod(st.name, "ε");
        }
        // For each transition, create a rule: CurrentState -> InputSymbol NextState.
        for (const auto& trans : st.transitions) {
            std::string symbol = fmt_symbol(trans.input_symbol);
            std::string rhs = symbol;
            if (trans.next_state < pda.states.size()) {
                const auto& next = pda.states[trans.next_state];
                if (symbol == "ε") {
                    rhs = "ε " + next.name;
                } else {
                    rhs = symbol + " " + next.name;
                }
                add_prod(st.name, rhs);
                // If the next state is accepting, we can also just consume the symbol and finish.
                if (next.accepting) {
                    add_prod(st.name, symbol);
                }
            } else {
                add_prod(st.name, symbol);
            }
        }
    }

    // Helper: Formats a rule as "LHS -> RHS1 | RHS2 | ..."
    auto emit_line = [&rules](const std::string& lhs, const std::set<std::string>& rhs_set) {
        if (rhs_set.empty()) return;
        std::string line = "  " + lhs + " -> ";
        bool first = true;
        for (const auto& rhs : rhs_set) {
            if (!first) line += " | ";
            first = false;
            line += rhs;
        }
        rules.push_back(line);
    };

    // Output the start rule first.
    auto s_it = productions.find("S");
    if (s_it != productions.end()) {
        emit_line("S", s_it->second);
    }

    // Output the rest of the rules.
    for (const auto& st : pda.states) {
        auto it = productions.find(st.name);
        if (it != productions.end()) {
            emit_line(st.name, it->second);
        }
    }

    return rules;
}

static void persist_rules_if_requested(const std::string& path, const std::vector<std::string>& lines) {
    if (path.empty()) return;
    std::ofstream out(path);
    if (!out.is_open()) {
        print_error("Failed to write grammar file: " + path);
    }
    for (const auto& line : lines) {
        out << line << "\n";
    }
}

// The JSON helpers, grammar loader and DOT/PDA parsers were moved to `utils.cpp`.
// They are declared in `utils.hpp` and implemented in `utils.cpp` to keep
// this file focused on the core algorithmic simulation and CLI logic.

// -----------------------------------------------------------------------------
// api/main.cpp - CLI helper used by the Go backend and for quick inspection
//
// Modes supported (select with `--mode <name>`):
//  - graph:  Parse a DOT file (DFA) and emit a JSON structure { nodes, edges }
//            Nodes include `is_start` and `is_accepting` flags. Used by backend
//            to power the visualizer.
//  - derivation: Given a CNF regular grammar and a comma-separated input sequence,
//            produce a human-readable derivation trace (used to show how a token
//            sequence maps to grammar productions).
//  - dfa:    Load a DOT DFA and step through comma-separated symbols; emits
//            a list of transitions (current_state, symbol, next_state) and a final
//            is_malicious flag based on whether the final state is accepting.
//  - pda:    Load a PDA (DOT) and simulate with explicit stack operations; returns
//            a trace of PUSH/POP/NO_OP operations and whether the input is accepted.
//
// The code below intentionally keeps parsing and JSON formatting code compact
// so it can be run as a portable CLI by the Go backend (`Runner`) which expects
// JSON output when `--json` is provided.
// -----------------------------------------------------------------------------

// --- PDA Simulation ---

struct SimulationState {
    size_t state_idx;
    size_t input_idx;
    std::vector<std::string> stack;
    std::vector<PDAStep> trace;
};

// simulate_pda: This function runs the Pushdown Automaton (PDA) simulation.
// It explores all possible paths the machine can take (breadth-first search) to see if the input is valid.
// If the input is valid, it returns the successful path (trace).
// If not, it returns the path that got the furthest, to help show where it failed.
PDATraceResult simulate_pda(const PDA& pda, const std::vector<std::string>& input) {
    // We use a queue to manage the different paths we are exploring.
    // Each item in the queue represents a "state" of the simulation:
    // - Which control state we are in (e.g., "Start", "TCP_Established")
    // - How much of the input we have processed so far
    // - The current contents of the stack (memory)
    // - The history of steps taken to get here
    std::deque<SimulationState> queue;
    
    // Start the simulation at the PDA's start state, with 0 input processed, an empty stack, and no history.
    queue.push_back({pda.start, 0, {}, {}});

    size_t max_steps = 50000; // A safety limit to stop the simulation if it runs too long (infinite loop protection).
    size_t steps_count = 0;

    // We keep track of the "best" attempt so far.
    // "Best" means the attempt that successfully processed the most input characters.
    // This is useful for error reporting if the input is rejected.
    size_t best_input_consumed = 0;
    std::vector<PDAStep> best_trace;

    // Keep processing states from the queue until there are none left or we hit the limit.
    while(!queue.empty()) {
        if (steps_count++ > max_steps) break; // Stop if we've done too much work.

        // Get the next state to explore from the front of the queue.
        SimulationState current = queue.front();
        queue.pop_front();

        // Check if this path has processed more input than our previous best.
        // If so, remember it as the new best path.
        if (current.input_idx > best_input_consumed) {
            best_input_consumed = current.input_idx;
            best_trace = current.trace;
        }

        // Check if we have successfully finished:
        // 1. We have processed all the input characters.
        // 2. The current state is marked as an "accepting" state (valid end state).
        if (current.input_idx == input.size() && pda.states[current.state_idx].accepting) {
            // Success! Return true and the history of steps.
            return {true, current.trace};
        }

        // Get the details of the current control state we are in.
        const auto& state = pda.states[current.state_idx];
        
        // Look at all the possible moves (transitions) allowed from this state.
        for (const auto& trans : state.transitions) {
            // Check if the input matches what this transition requires.
            bool input_match = false;
            bool consumes_input = false;

            if (trans.input_symbol == "ε") {
                // "ε" (epsilon) means this move doesn't require any input (it's automatic).
                input_match = true;
            } else if (current.input_idx < input.size() && trans.input_symbol == input[current.input_idx]) {
                // The transition requires a specific symbol, and it matches the next one in our input.
                input_match = true;
                consumes_input = true; // This move will use up one input character.
            }

            if (!input_match) continue; // If input doesn't match, we can't take this path.

            // Check if the stack matches what this transition requires.
            // Some moves require popping a specific item from the top of the stack.
            bool stack_match = false;
            if (trans.pop_symbol == "ε") {
                // "ε" means we don't need to pop anything.
                stack_match = true;
            } else if (!current.stack.empty() && current.stack.back() == trans.pop_symbol) {
                // The top of the stack matches the required symbol.
                stack_match = true;
            }

            if (!stack_match) continue; // If stack doesn't match, we can't take this path.

            // If we get here, this transition is valid!
            // Create a new simulation state representing the result of taking this move.
            SimulationState next = current;
            next.state_idx = trans.next_state; // Move to the new control state.
            if (consumes_input) next.input_idx++; // Advance input if we used a character.

            // Perform the stack "POP" operation if required.
            if (trans.pop_symbol != "ε") {
                next.stack.pop_back(); // Remove the top item.
            }

            // Perform the stack "PUSH" operation.
            // We push symbols in reverse order so the first one ends up on top.
            for (auto it = trans.push_symbols.rbegin(); it != trans.push_symbols.rend(); ++it) {
                next.stack.push_back(*it);
            }

            // Record this step in the history trace so we can show the user what happened.
            PDAStep step;
            step.current_state = state.name;
            step.next_state = pda.states[trans.next_state].name;
            step.symbol = consumes_input ? input[current.input_idx] : "ε";
            step.stack_after = next.stack;

            // Label the operation type for the UI (PUSH, POP, or just moving).
            if (!trans.push_symbols.empty()) step.op = "PUSH";
            else if (trans.pop_symbol != "ε") step.op = "POP";
            else step.op = "NO_OP";

            next.trace.push_back(step);

            // Add this new state to the queue to be explored later.
            queue.push_back(next);
        }
    }

    // If we empty the queue without finding a solution, the input is invalid.
    // Return false, but provide the "best" trace we found to help debug.
    return {false, best_trace};
}

// main: The entry point of the program.
// It reads command-line arguments to decide which mode to run.
int main(int argc, char** argv) {
    std::string mode;
    std::string input;
    std::string state;
    std::string grammar_path = "grammar.txt";
    std::string dot_path = "automaton.dot";

    // Loop through all arguments passed to the program.
    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        // Check for flags like --mode, --input, etc. and store their values.
        if (a.rfind("--mode", 0) == 0) {
            if (i + 1 < argc) mode = argv[++i];
        } else if (a.rfind("--input", 0) == 0) {
            if (i + 1 < argc) input = argv[++i];
        } else if (a.rfind("--state", 0) == 0) {
            if (i + 1 < argc) state = argv[++i];
        } else if (a.rfind("--grammar", 0) == 0) {
            if (i + 1 < argc) grammar_path = argv[++i];
        } else if (a.rfind("--dot", 0) == 0) {
            if (i + 1 < argc) dot_path = argv[++i];
        } else if (a == "--json") {
            // No-op, always JSON (we keep this for compatibility).
        }
    }

    // Mode: graph
    // This mode reads a DOT file (which describes a graph) and converts it into JSON.
    // The frontend uses this JSON to draw the graph on the screen.
    if (mode == "graph") {
        std::ifstream in(dot_path);
        if (!in.is_open()) print_error("Failed to open DOT file: " + dot_path);

        std::vector<std::string> nodes_json;
        std::vector<std::string> edges_json;
        std::string start_node;
        std::string line;

        // Read the file line by line.
        while (std::getline(in, line)) {
            // Clean up whitespace.
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);

            // Look for the special start marker (e.g., "__start -> s0").
            if (line.find("__start ->") == 0) {
                size_t arrow = line.find("->");
                size_t semi = line.find(";");
                if (arrow != std::string::npos && semi != std::string::npos) {
                    start_node = line.substr(arrow + 2, semi - (arrow + 2));
                    start_node.erase(0, start_node.find_first_not_of(" \t"));
                    start_node.erase(start_node.find_last_not_of(" \t") + 1);
                }

            // Look for edges (connections between nodes), e.g., "s0 -> s1".
            } else if (line.find("->") != std::string::npos) {
                if (line.find("__start") == 0) continue; // Skip the start marker line itself.

                size_t arrow = line.find("->");
                size_t bracket = line.find("[");
                size_t label_pos = line.find("label=\"");

                // If it looks like a valid edge with a label...
                if (arrow != std::string::npos && bracket != std::string::npos && label_pos != std::string::npos) {
                    // Extract the source and target node names.
                    std::string src = line.substr(0, arrow);
                    std::string tgt = line.substr(arrow + 2, bracket - (arrow + 2));

                    // Clean up names.
                    src.erase(0, src.find_first_not_of(" \t"));
                    src.erase(src.find_last_not_of(" \t") + 1);
                    tgt.erase(0, tgt.find_first_not_of(" \t"));
                    tgt.erase(tgt.find_last_not_of(" \t") + 1);

                    // Extract the label text (what is written on the arrow).
                    size_t label_end = line.find("\"", label_pos + 7);
                    std::string lbl = line.substr(label_pos + 7, label_end - (label_pos + 7));

                    // Format as a JSON object for the edge.
                    std::ostringstream e;
                    e << "{ \"source\": \"" << json_escape(src) << "\", ";
                    e << "\"target\": \"" << json_escape(tgt) << "\", ";
                    e << "\"label\": \"" << json_escape(lbl) << "\" }";
                    edges_json.push_back(e.str());
                }

            // Look for node definitions, e.g., "s0 [label=...]".
            } else if (line.find("[") != std::string::npos && line.find("label=") != std::string::npos) {
                if (line.find("__start") == 0) continue;
                if (line.find("node [") == 0) continue;

                size_t bracket = line.find("[");
                std::string id = line.substr(0, bracket);
                id.erase(0, id.find_first_not_of(" \t"));
                id.erase(id.find_last_not_of(" \t") + 1);

                size_t label_pos = line.find("label=\"");
                if (label_pos != std::string::npos) {
                    size_t label_end = line.find("\"", label_pos + 7);
                    std::string label_raw = line.substr(label_pos + 7, label_end - (label_pos + 7));
                    // Take only the first line of the label.
                    std::string label = label_raw.substr(0, label_raw.find("\\n"));

                    // Check if it's an accepting state (marked by doublecircle).
                    bool is_accepting = line.find("doublecircle") != std::string::npos;

                    // Format as a JSON object for the node.
                    std::ostringstream n;
                    n << "{ \"id\": \"" << json_escape(id) << "\", ";
                    n << "\"label\": \"" << json_escape(label) << "\", ";
                    n << "\"is_accepting\": " << (is_accepting ? "true" : "false") << ", ";
                    n << "\"is_start\": " << (id == start_node ? "true" : "false") << " }";
                    nodes_json.push_back(n.str());
                }
            }
        }

        // Ensure the start node is correctly marked in the JSON list.
        if (!start_node.empty()) {
             for (auto& n : nodes_json) {
                 if (n.find("\"id\": \"" + start_node + "\"") != std::string::npos) {
                     size_t pos = n.find("\"is_start\": false");
                     if (pos != std::string::npos) {
                         n.replace(pos, 17, "\"is_start\": true");
                     }
                 }
             }
        }

        // Output the final JSON structure containing nodes and edges.
        std::cout << "{ \"nodes\": [";
        for (size_t i = 0; i < nodes_json.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << nodes_json[i];
        }
        std::cout << "], \"edges\": [";
        for (size_t i = 0; i < edges_json.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << edges_json[i];
        }
        std::cout << "] }" << std::endl;

    }
    // Mode: grammar
    // Reads a grammar file and outputs it as a JSON list of rules.
    else if (mode == "grammar") {
        std::ifstream in(grammar_path);
        if (!in.is_open()) {
            print_error("Failed to open grammar file: " + grammar_path);
        }

        std::vector<std::string> lines;
        std::string line;
        while (std::getline(in, line)) {
            lines.push_back(line);
        }

        std::cout << "{ \"rules\": [";
        for (size_t i = 0; i < lines.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << "\"" << json_escape(lines[i]) << "\"";
        }
        std::cout << "] }" << std::endl;
    }
    // Mode: pda_grammar
    // Loads a PDA, converts its logic into grammar rules, and outputs them.
    else if (mode == "pda_grammar") {
        PDA pda;
        std::string err;
        if (!load_dot_pda(dot_path, pda, err)) {
            print_error("Failed to load PDA from DOT: " + err);
        }

        auto rules = build_pda_grammar_rules(pda, dot_path);
        persist_rules_if_requested(grammar_path, rules);

        std::cout << "{ \"rules\": [";
        for (size_t i = 0; i < rules.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << "\"" << json_escape(rules[i]) << "\"";
        }
        std::cout << "] }" << std::endl;
    }
    // Mode: derivation
    // Takes a sequence of inputs and explains how the grammar produces them step-by-step.
    else if (mode == "derivation") {
        Grammar g;
        if (!load_grammar_for_derivation(grammar_path, g)) {
            print_error("Failed to load grammar");
        }

        // Parse the comma-separated input string into a list.
        std::vector<std::string> seq;
        std::stringstream ss(input);
        std::string item;
        while (std::getline(ss, item, ',')) {
            seq.push_back(trim(item));
        }

        // Calculate the derivation steps.
        auto derivation = build_derivation_steps(g, seq);

        // Output the steps as JSON.
        std::cout << "{ \"steps\": [";
        for (size_t i = 0; i < derivation.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << "\"" << json_escape(derivation[i]) << "\"";
        }
        std::cout << "] }" << std::endl;

    }
    // Mode: pda_derivation
    // Similar to derivation, but specifically for the PDA's grammar.
    else if (mode == "pda_derivation") {
        Grammar g;
        bool loaded = load_grammar_for_derivation(grammar_path, g);
        if (!loaded && !dot_path.empty()) {
            PDA pda;
            std::string err;
            if (!load_dot_pda(dot_path, pda, err)) {
                print_error("Failed to load PDA for derivation: " + err);
            }
            auto rules = build_pda_grammar_rules(pda, dot_path);
            persist_rules_if_requested(grammar_path, rules);
            loaded = load_grammar_for_derivation(grammar_path, g);
        }

        if (!loaded) {
            print_error("Failed to load PDA grammar for derivation");
        }

        std::vector<std::string> seq;
        std::stringstream iss(input);
        std::string tok;
        while (iss >> tok) seq.push_back(trim(tok));

        auto derivation = build_derivation_steps(g, seq);

        std::cout << "{ \"steps\": [";
        for (size_t i = 0; i < derivation.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << "\"" << json_escape(derivation[i]) << "\"";
        }
        std::cout << "] }" << std::endl;

    }
    // Mode: dfa
    // Simulates a Deterministic Finite Automaton (DFA).
    // It steps through the input symbols one by one and tracks the state changes.
    else if (mode == "dfa") {
        GrammarDFA gdfa;
        std::string err;
        if (!load_dot_dfa(dot_path, gdfa, err)) {
            print_error("Failed to load DFA from DOT: " + err);
        }

        // If no start state is given, use the default one.
        if (state.empty()) state = gdfa.names[gdfa.start];
        
        // Parse input.
        std::vector<std::string> seq;
        std::stringstream ss(input);
        std::string item;
        while (std::getline(ss, item, ',')) {
            seq.push_back(trim(item));
        }
        
        // Find the starting state index.
        size_t cur_idx = 0;
        if (gdfa.idx.find(state) != gdfa.idx.end()) {
            cur_idx = gdfa.idx[state];
        } else {
            print_error("Unknown state: " + state);
        }

        std::cout << "{ \"steps\": [";
        bool first_step = true;

        // Process each symbol in the sequence.
        for (const auto& sym : seq) {
            if (!first_step) std::cout << ", ";
            first_step = false;

            std::string current_state_name = gdfa.names[cur_idx];
            std::string next_state_name;

            // Check if there is a valid transition for this symbol.
            auto it = gdfa.trans[cur_idx].find(sym);
            if (it != gdfa.trans[cur_idx].end()) {
                cur_idx = it->second; // Move to the next state.
                next_state_name = gdfa.names[cur_idx];
            } else {
                // No transition found: stay in the same state (visualizer behavior).
                next_state_name = current_state_name; 
            }

            // Output the step details.
            std::cout << "{ \"current_state\": \"" << json_escape(current_state_name) << "\", ";
            std::cout << "\"symbol\": \"" << json_escape(sym) << "\", ";
            std::cout << "\"next_state\": \"" << json_escape(next_state_name) << "\" }";
        }

        // Check if the final state is "accepting" (malicious).
        bool is_malicious = gdfa.accepting[cur_idx];
        
        std::cout << "], \"final_state\": \"" << json_escape(gdfa.names[cur_idx]) << "\", ";
        std::cout << "\"is_malicious\": " << (is_malicious ? "true" : "false") << ", ";
        std::cout << "\"label\": \"" << (is_malicious ? "Malicious" : "Benign") << "\" }" << std::endl;

    }
    // Mode: pda
    // Simulates a Pushdown Automaton (PDA).
    // It uses the simulate_pda function to check if the input is valid.
    else if (mode == "pda") {
        // Load the PDA definition.
        PDA pda;
        std::string err;
        if (!load_dot_pda(dot_path, pda, err)) {
            print_error("Failed to load PDA from DOT: " + err);
        }

        // Parse input (space-separated).
        std::vector<std::string> seq;
        std::stringstream iss(input);
        std::string tok;
        while (iss >> tok) seq.push_back(tok);

        // Run the simulation.
        PDATraceResult res = simulate_pda(pda, seq);

        // Output the result (valid/invalid) and the trace of steps.
        std::cout << "{ \"valid\": " << (res.ok ? "true" : "false") << ", \"steps\": [";
        for (size_t i = 0; i < res.steps.size(); ++i) {
            if (i > 0) std::cout << ", ";
            const auto& step = res.steps[i];
            std::cout << "{ \"op\": \"" << json_escape(step.op) << "\", ";
            std::cout << "\"symbol\": \"" << json_escape(step.symbol) << "\", ";
            std::cout << "\"stack\": [";
            for (size_t j = 0; j < step.stack_after.size(); ++j) {
                if (j > 0) std::cout << ", ";
                std::cout << "\"" << json_escape(step.stack_after[j]) << "\"";
            }
            std::cout << "], \"current_state\": \"" << json_escape(step.current_state) << "\", ";
            std::cout << "\"next_state\": \"" << json_escape(step.next_state) << "\" }";
        }
        std::cout << "] }" << std::endl;

    } else {
        print_error("Unknown mode: " + mode);
    }

    return 0;
}
