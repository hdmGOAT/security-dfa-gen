#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <regex>
#include <map>
#include <deque>

#include "core.hpp"
#include "utils.hpp"

using namespace automata_security;

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

// simulate_pda: breadth-first exploration of PDA control states and stacks
// Returns the first accepting trace found, or the most-progressing trace when
// no accepting run exists (helps the UI show where execution failed).
// simulate_pda performs a breadth-first search over PDA configurations.
// We explore possible transitions non-deterministically and return the first
// accepting trace found. If no accepting run exists, we return the "best"
// trace (the one that consumed the most input) to help UI debugging.
PDATraceResult simulate_pda(const PDA& pda, const std::vector<std::string>& input) {
    // BFS queue of configurations: (state index, next input index, stack, trace so far)
    std::deque<SimulationState> queue;
    queue.push_back({pda.start, 0, {}, {}});

    size_t max_steps = 50000; // Safety limit to prevent pathological loops
    size_t steps_count = 0;

    // Track the best (furthest-progressing) partial trace so we can return it
    // when no accepting run is found; this improves UX by showing where the
    // PDA got stuck.
    size_t best_input_consumed = 0;
    std::vector<PDAStep> best_trace;

    while(!queue.empty()) {
        if (steps_count++ > max_steps) break; // bail out if too many steps

        SimulationState current = queue.front();
        queue.pop_front();

        // Update best progress
        if (current.input_idx > best_input_consumed) {
            best_input_consumed = current.input_idx;
            best_trace = current.trace;
        }

        // Accepting condition: consumed all input and in accepting control state
        if (current.input_idx == input.size() && pda.states[current.state_idx].accepting) {
            return {true, current.trace};
        }

        const auto& state = pda.states[current.state_idx];
        // Examine each outgoing transition from the current control state
        for (const auto& trans : state.transitions) {
            // Determine if the transition matches the current input symbol
            bool input_match = false;
            bool consumes_input = false;

            if (trans.input_symbol == "ε") {
                // ε-transitions do not consume input
                input_match = true;
            } else if (current.input_idx < input.size() && trans.input_symbol == input[current.input_idx]) {
                input_match = true;
                consumes_input = true;
            }

            if (!input_match) continue; // skip if input doesn't match

            // Check stack/pop condition: either pop ε or top matches the required symbol
            bool stack_match = false;
            if (trans.pop_symbol == "ε") {
                stack_match = true;
            } else if (!current.stack.empty() && current.stack.back() == trans.pop_symbol) {
                stack_match = true;
            }

            if (!stack_match) continue; // skip if stack doesn't match

            // Apply the transition to form a new configuration
            SimulationState next = current;
            next.state_idx = trans.next_state;
            if (consumes_input) next.input_idx++;

            // Pop from stack if required
            if (trans.pop_symbol != "ε") {
                next.stack.pop_back();
            }

            // Push symbols onto stack in reverse order so the first symbol from the
            // RHS becomes the top of the stack.
            for (auto it = trans.push_symbols.rbegin(); it != trans.push_symbols.rend(); ++it) {
                next.stack.push_back(*it);
            }

            // Record the PDA step for tracing/debugging
            PDAStep step;
            step.current_state = state.name;
            step.next_state = pda.states[trans.next_state].name;
            step.symbol = consumes_input ? input[current.input_idx] : "ε";
            step.stack_after = next.stack;

            if (!trans.push_symbols.empty()) step.op = "PUSH";
            else if (trans.pop_symbol != "ε") step.op = "POP";
            else step.op = "NO_OP";

            next.trace.push_back(step);

            // Enqueue next configuration for exploration
            queue.push_back(next);
        }
    }

    // No accepting run found: return the best partial trace to help debugging
    return {false, best_trace};
}

int main(int argc, char** argv) {
    std::string mode;
    std::string input;
    std::string state;
    std::string grammar_path = "grammar.txt";
    std::string dot_path = "automaton.dot";

    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
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
            // No-op, always JSON
        }
    }

    // Mode: graph
    // Parse a DOT file line-by-line and assemble JSON arrays for nodes and edges.
    // The parser looks for the special `__start -> <node>;` line to detect the
    // start state and uses node attributes (label, doublecircle) to set
    // descriptive fields for the UI.
    if (mode == "graph") {
        std::ifstream in(dot_path);
        if (!in.is_open()) print_error("Failed to open DOT file: " + dot_path);

        // Use simple string matching instead of regex to avoid raw string literal issues
        // std::regex node_re(R"(\s*(\w+)\s*\[label="([^"]+)"(.*)\];)");
        
        std::vector<std::string> nodes_json;
        std::vector<std::string> edges_json;
        std::string start_node;
        std::string line;

        // Read DOT file line-by-line and detect special markers, node and edge
        // declarations. We perform simple string matching rather than full DOT
        // parsing for robustness and portability.
        while (std::getline(in, line)) {
            // Trim whitespace from both ends
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);

            // Detect start edge: `__start -> sX;` and remember the target id.
            if (line.find("__start ->") == 0) {
                // Example: `__start -> s4;`
                size_t arrow = line.find("->");
                size_t semi = line.find(";");
                if (arrow != std::string::npos && semi != std::string::npos) {
                    start_node = line.substr(arrow + 2, semi - (arrow + 2));
                    start_node.erase(0, start_node.find_first_not_of(" \t"));
                    start_node.erase(start_node.find_last_not_of(" \t") + 1);
                }

            // Edge lines: `s0 -> s5 [label="..."];` (ignore the __start pseudo-node)
            } else if (line.find("->") != std::string::npos) {
                if (line.find("__start") == 0) continue; // already handled

                size_t arrow = line.find("->");
                size_t bracket = line.find("[");
                size_t label_pos = line.find("label=\"");

                // We expect an edge line with a bracketed attribute list and a
                // label attribute; if these are not present we skip the line.
                if (arrow != std::string::npos && bracket != std::string::npos && label_pos != std::string::npos) {
                    // Extract source and target node ids
                    std::string src = line.substr(0, arrow);
                    std::string tgt = line.substr(arrow + 2, bracket - (arrow + 2));

                    // Trim whitespace from node ids
                    src.erase(0, src.find_first_not_of(" \t"));
                    src.erase(src.find_last_not_of(" \t") + 1);
                    tgt.erase(0, tgt.find_first_not_of(" \t"));
                    tgt.erase(tgt.find_last_not_of(" \t") + 1);

                    // Extract label value inside label="..."
                    size_t label_end = line.find("\"", label_pos + 7);
                    std::string lbl = line.substr(label_pos + 7, label_end - (label_pos + 7));

                    std::ostringstream e;
                    e << "{ \"source\": \"" << json_escape(src) << "\", ";
                    e << "\"target\": \"" << json_escape(tgt) << "\", ";
                    e << "\"label\": \"" << json_escape(lbl) << "\" }";
                    edges_json.push_back(e.str());
                }

            // Node declaration lines: `s0 [label="s0\n+..." ...];`
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
                    // Label raw contains the visible label (we take only the first line before \n)
                    std::string label = label_raw.substr(0, label_raw.find("\\n"));

                        // Detect accepting (doublecircle) style. DOT exports use the
                        // doublecircle shape attribute to indicate accepting states
                        // in the visualizer, so we detect that text here.
                        bool is_accepting = line.find("doublecircle") != std::string::npos;

                    std::ostringstream n;
                    n << "{ \"id\": \"" << json_escape(id) << "\", ";
                    n << "\"label\": \"" << json_escape(label) << "\", ";
                    n << "\"is_accepting\": " << (is_accepting ? "true" : "false") << ", ";
                    n << "\"is_start\": " << (id == start_node ? "true" : "false") << " }";
                    nodes_json.push_back(n.str());
                }
            }
        }

        // Fix start node flag
        if (!start_node.empty()) {
             for (auto& n : nodes_json) {
                 if (n.find("\"id\": \"" + start_node + "\"") != std::string::npos) {
                     // This is a hacky replace, but sufficient for generated JSON
                     size_t pos = n.find("\"is_start\": false");
                     if (pos != std::string::npos) {
                         n.replace(pos, 17, "\"is_start\": true");
                     }
                 }
             }
        }

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
    // Mode: derivation
    // Given a CNF regular grammar, produce a simple left-to-right derivation
    // trace for a comma-separated input sequence. The algorithm picks matching
    // productions heuristically to produce a plausible derivation for display.
    else if (mode == "derivation") {
        Grammar g;
        if (!load_grammar_for_derivation(grammar_path, g)) {
            print_error("Failed to load grammar");
        }

        // Input is comma separated symbols
        std::vector<std::string> seq;
        std::stringstream ss(input);
        std::string item;
        while (std::getline(ss, item, ',')) {
            seq.push_back(trim(item));
        }

        std::vector<std::string> derivation;
        derivation.push_back("S");
        
        std::string current_sentential_form = "S";
        std::string processed_prefix = "";
        std::string current_nt = "S";

        // Simple linear derivation for Regular Grammar
        for (size_t seq_idx = 0; seq_idx < seq.size(); ++seq_idx) {
            const auto& sym = seq[seq_idx];
            bool is_last = (seq_idx == seq.size() - 1);
            
            // Find production from current_nt that matches sym
            bool found = false;
            if (g.productions.find(current_nt) == g.productions.end()) break;

            // We need to pick the best production.
            // Candidates:
            struct Candidate {
                std::vector<std::string> prod;
                std::string next_nt;
            };
            std::vector<Candidate> candidates;

            for (const auto& prod : g.productions[current_nt]) {
                if (prod.empty()) continue;
                
                // Check match
                std::string first = prod[0];
                bool match = false;
                if (first[0] == 'T' && g.terminals.count(first)) {
                    if (g.terminals[first] == sym) match = true;
                } else if (first == sym) {
                    match = true;
                }

                if (match) {
                    std::string next_nt;
                    for (size_t i = 0; i < prod.size(); ++i) {
                        if (g.productions.count(prod[i])) next_nt = prod[i];
                    }
                    candidates.push_back({prod, next_nt});
                }
            }

            // Selection logic
            const std::vector<std::string>* selected_prod = nullptr;
            std::string selected_next_nt;
            // Selection logic: heuristically pick a production among candidates.
            // - If we're at the last input symbol, prefer a terminating
            //   production (no next nonterminal) so the derivation can finish.
            // - Otherwise prefer productions that transition to another
            //   nonterminal so subsequent symbols can be matched.
            for (const auto& cand : candidates) {
                if (is_last) {
                    if (cand.next_nt.empty()) {
                        selected_prod = &cand.prod;
                        selected_next_nt = cand.next_nt;
                        break; 
                    }
                } else {
                    if (!cand.next_nt.empty()) {
                        selected_prod = &cand.prod;
                        selected_next_nt = cand.next_nt;
                        break;
                    }
                }
            }
            
            // Fallback: if no preferred found, just take the first one (or any)
            // Fallback: if no heuristic selection succeeded, fall back to the
            // first candidate. This keeps the derivation monotonic rather than
            // failing fast and yields a plausible trace for display.
            if (!selected_prod && !candidates.empty()) {
                selected_prod = &candidates[0].prod;
                selected_next_nt = candidates[0].next_nt;
            }

            if (selected_prod) {
                const auto& prod = *selected_prod;
                // Found it.
                // 1. Replace NT with RHS
                std::string rhs_str;
                std::string next_nt = selected_next_nt;
                
                // If we used a T-rule:
                std::string first = prod[0];
                if (first[0] == 'T') {
                    // Intermediate step with T
                    std::string step1_rhs;
                    for (size_t i = 0; i < prod.size(); ++i) {
                        if (i > 0) step1_rhs += " ";
                        step1_rhs += prod[i];
                    }
                    derivation.push_back(processed_prefix + step1_rhs);
                }

                // Final step for this symbol
                std::string step2_rhs;
                for (size_t i = 0; i < prod.size(); ++i) {
                    if (i > 0) step2_rhs += " ";
                    if (prod[i][0] == 'T' && g.terminals.count(prod[i])) {
                        step2_rhs += g.terminals[prod[i]];
                    } else {
                        step2_rhs += prod[i];
                    }
                }
                
                std::string full_step = processed_prefix + step2_rhs;
                // Avoid duplicate if T-rule wasn't used or same
                if (derivation.back() != full_step) {
                    derivation.push_back(full_step);
                }

                processed_prefix += sym + " ";
                current_nt = next_nt;
                found = true;
            }
            
            if (!found) break;
            if (current_nt.empty() && !is_last) break; // Terminated early?
        }

        std::cout << "{ \"steps\": [";
        for (size_t i = 0; i < derivation.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << "\"" << json_escape(derivation[i]) << "\"";
        }
        std::cout << "] }" << std::endl;

    }
    // Mode: dfa
    // Load a DFA from DOT (via load_dot_dfa) and step through comma-separated
    // symbols starting from the provided state (or the DFA start state if none
    // supplied). Emit per-symbol steps and final classification (is_malicious).
    else if (mode == "dfa") {
        GrammarDFA gdfa;
        std::string err;
        if (!load_dot_dfa(dot_path, gdfa, err)) {
            print_error("Failed to load DFA from DOT: " + err);
        }

    // If no explicit start state was provided via `--state`, start from
    // the grammar/DFA's canonical start (typically 'S'). The backend UI
    // can pass a specific state name to resume stepping from an arbitrary
    // node for interactive debugging.
    if (state.empty()) state = gdfa.names[gdfa.start];
        
        // Input is comma separated symbols
        std::vector<std::string> seq;
        std::stringstream ss(input);
        std::string item;
        while (std::getline(ss, item, ',')) {
            seq.push_back(trim(item));
        }
        
        size_t cur_idx = 0;
        if (gdfa.idx.find(state) != gdfa.idx.end()) {
            cur_idx = gdfa.idx[state];
        } else {
            print_error("Unknown state: " + state);
        }

        std::cout << "{ \"steps\": [";
        bool first_step = true;

        for (const auto& sym : seq) {
            if (!first_step) std::cout << ", ";
            first_step = false;

            std::string current_state_name = gdfa.names[cur_idx];
            std::string next_state_name;

            auto it = gdfa.trans[cur_idx].find(sym);
            if (it != gdfa.trans[cur_idx].end()) {
                cur_idx = it->second;
                next_state_name = gdfa.names[cur_idx];
            } else {
                // No transition found for this symbol. Historically the CLI
                // simply kept the DFA in the same visual state which allows the
                // UI to show the symbol that couldn't be consumed. A more
                // strict behavior would move to a sink or report an error,
                // but keeping the current state preserves prior visual traces.
                next_state_name = current_state_name; 
            }

            std::cout << "{ \"current_state\": \"" << json_escape(current_state_name) << "\", ";
            std::cout << "\"symbol\": \"" << json_escape(sym) << "\", ";
            std::cout << "\"next_state\": \"" << json_escape(next_state_name) << "\" }";
        }

        bool is_malicious = gdfa.accepting[cur_idx];
        
        std::cout << "], \"final_state\": \"" << json_escape(gdfa.names[cur_idx]) << "\", ";
        std::cout << "\"is_malicious\": " << (is_malicious ? "true" : "false") << ", ";
        std::cout << "\"label\": \"" << (is_malicious ? "Malicious" : "Benign") << "\" }" << std::endl;

    }
    // Mode: pda
    // Load a PDA and simulate it using `simulate_pda`. The output is a JSON
    // sequence of stack operations and a final `valid` boolean.
    else if (mode == "pda") {
        // Load PDA from DOT and simulate using structured PDA transitions
        PDA pda;
        std::string err;
        if (!load_dot_pda(dot_path, pda, err)) {
            print_error("Failed to load PDA from DOT: " + err);
        }

        // Input is space separated symbols (history). Use stringstream >> to skip extra spaces.
        std::vector<std::string> seq;
        std::stringstream iss(input);
        std::string tok;
        while (iss >> tok) seq.push_back(tok);

        PDATraceResult res = simulate_pda(pda, seq);

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
