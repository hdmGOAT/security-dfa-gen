#include "core.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace automata_security {

std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

void GrammarDFA::add_state_if_missing(const std::string& name) {
    if (idx.find(name) != idx.end()) return;
    std::size_t id = names.size();
    names.push_back(name);
    idx[name] = id;
    trans.emplace_back();
    accepting.push_back(false);
}

void GrammarDFA::set_start(const std::string& name) {
    add_state_if_missing(name);
    start = idx[name];
}

void GrammarDFA::set_accepting(const std::string& name) {
    add_state_if_missing(name);
    accepting[idx[name]] = true;
}

void GrammarDFA::add_transition(const std::string& from, const std::string& on, const std::string& to) {
    add_state_if_missing(from);
    add_state_if_missing(to);
    trans[idx[from]][on] = idx[to];
}

std::pair<bool, std::string> GrammarDFA::classify_with_reason(const std::vector<std::string>& seq) const {
    if (names.empty()) return {false, "empty grammar"};
    std::size_t cur = start;
    for (std::size_t i = 0; i < seq.size(); ++i) {
        const auto& sym = seq[i];
        auto it = trans[cur].find(sym);
        if (it == trans[cur].end()) {
            std::ostringstream oss;
            oss << "no transition on '" << sym << "' from state '" << names[cur] << "' at position " << i;
            return {false, oss.str()};
        }
        cur = it->second;
    }
    if (accepting[cur]) return {true, "accepted"};
    std::ostringstream oss;
    oss << "ended in non-accepting state '" << names[cur] << "'";
    return {false, oss.str()};
}

bool load_cnf_grammar(const std::string& path, GrammarDFA& out, std::string& err) {
    std::ifstream in(path);
    if (!in.is_open()) { err = "failed to open grammar file"; return false; }

    std::unordered_map<std::string, std::string> T_to_term;
    std::vector<std::pair<std::string, std::string>> binary_rules; // lhs -> "Tn A#"
    std::vector<std::pair<std::string, std::string>> terminal_rules; // lhs -> terminal
    std::unordered_set<std::string> nonterminals;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line.rfind("#", 0) == 0) continue; // comment
        auto arrow = line.find("->");
        if (arrow == std::string::npos) continue;
        std::string lhs = trim(line.substr(0, arrow));
        std::string rhs = trim(line.substr(arrow + 2));
        // terminal helper
        if (lhs.size() > 0 && lhs[0] == 'T') {
            // rhs might be quoted; take first token
            rhs = trim(rhs);
            rhs = unquote(rhs);
            T_to_term[lhs] = rhs;
            // nonterminals.insert(lhs); // Don't add Tn as states
            continue;
        }
        // lhs is nonterminal
        nonterminals.insert(lhs);
        // split alternatives
        size_t pos = 0;
        while (pos < rhs.size()) {
            auto next = rhs.find('|', pos);
            std::string alt = (next == std::string::npos) ? rhs.substr(pos) : rhs.substr(pos, next - pos);
            alt = trim(alt);
            if (alt == "ε") {
                terminal_rules.emplace_back(lhs, "ε");
            } else {
                // tokenise by whitespace
                std::istringstream iss(alt);
                std::vector<std::string> toks;
                std::string tk;
                while (iss >> tk) toks.push_back(tk);
                if (toks.size() == 1) {
                    std::string atom = toks[0];
                    if (!atom.empty() && atom[0] == 'T') {
                        // reference to Tn -> terminal
                        terminal_rules.emplace_back(lhs, atom);
                    } else {
                        terminal_rules.emplace_back(lhs, unquote(atom));
                    }
                } else if (toks.size() == 2) {
                    // expect Tn Nonterm
                    binary_rules.emplace_back(lhs, toks[0] + " " + toks[1]);
                }
            }
            if (next == std::string::npos) break;
            pos = next + 1;
        }
    }

    // create states
    for (const auto& nt : nonterminals) out.add_state_if_missing(nt);
    
    // Add Accept state for terminal transitions
    out.set_accepting("Accept");

    // set start to S if exists, otherwise first nonterminal
    if (out.idx.find("S") != out.idx.end()) out.start = out.idx["S"]; else if (!out.names.empty()) out.start = 0;

    // apply terminal rules
    for (const auto& p : terminal_rules) {
        const auto& lhs = p.first;
        const auto& atom = p.second;
        if (atom == "ε") {
            out.set_accepting(lhs);
            continue;
        }
        
        std::string term;
        if (!atom.empty() && atom[0] == 'T') {
            auto it = T_to_term.find(atom);
            if (it != T_to_term.end()) {
                term = it->second;
            } else {
                continue;
            }
        } else {
            term = atom;
        }
        out.add_transition(lhs, term, "Accept");
    }

    // apply binary rules -> create transitions: lhs --terminal--> rhs_state
    for (const auto& p : binary_rules) {
        const auto& lhs = p.first;
        const std::string alt = p.second; // "Tn A#"
        std::istringstream iss(alt);
        std::string t0, t1;
        iss >> t0 >> t1;
        std::string term;
        if (!t0.empty() && t0[0] == 'T') {
            auto it = T_to_term.find(t0);
            if (it != T_to_term.end()) term = it->second; else term = t0;
        } else {
            term = unquote(t0);
        }
        out.add_transition(lhs, term, t1);
    }

    return true;
}

PDAResult validate_pda_sequence(const std::vector<std::string>& seq) {
    std::vector<std::string> stack;
    for (size_t i = 0; i < seq.size(); ++i) {
        const auto& s = seq[i];
        if (s.rfind("state=", 0) == 0) {
            if (s == "state=S0") {
                stack.push_back(s);
            } else if (s == "state=SF") {
                if (stack.empty()) {
                    return {false, "pop without matching push at position " + std::to_string(i)};
                }
                stack.pop_back();
            }
        }
    }
    if (!stack.empty()) {
        return {false, "final stack not empty (" + std::to_string(stack.size()) + " unmatched pushes)"};
    }
    return {true, "accepted"};
}

PDATraceResult validate_pda_sequence_with_trace(const std::vector<std::string>& seq) {
    std::vector<std::string> stack;
    PDATraceResult result;
    // Simple control-state for PDA visualization: Start -> TCP/UDP/OTHER based on proto= symbols
    std::string control_state = "Start";
    
    for (size_t i = 0; i < seq.size(); ++i) {
        const auto& s = seq[i];
        PDAStep step;
        step.symbol = s;
        step.op = "NO_OP";
        // record current control state before processing this symbol
        step.current_state = control_state;

        // determine provisional next control state
        std::string next_control_state = control_state;
        if (s.rfind("proto=", 0) == 0) {
            auto proto_val = s.substr(std::string("proto=").size());
            if (proto_val == "tcp") next_control_state = "TCP";
            else if (proto_val == "udp") next_control_state = "UDP";
            else next_control_state = "OTHER";
        }

        if (s.rfind("state=", 0) == 0) {
            if (s == "state=S0") {
                stack.push_back(s);
                step.op = "PUSH";
            } else if (s == "state=SF") {
                if (stack.empty()) {
                    step.op = "POP_ERROR";
                    step.stack_after = stack;
                    step.next_state = next_control_state;
                    result.steps.push_back(step);
                    result.ok = false;
                    return result;
                }
                stack.pop_back();
                step.op = "POP";
            }
        }
        step.stack_after = stack;
        // finalize next_state and update control_state
        step.next_state = next_control_state;
        control_state = next_control_state;
        result.steps.push_back(step);
    }
    
    if (!stack.empty()) {
        result.ok = false;
    }
    return result;
}

} // namespace automata_security
