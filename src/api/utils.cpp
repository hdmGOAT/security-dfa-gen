#include "utils.hpp"
#include "core.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>

using namespace std;

namespace automata_security {

string json_escape(const string& s) {
    ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    o << "\\u" << hex << (int)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();

}



void print_error(const string& msg) {
    cout << "{ \"error\": \"" << json_escape(msg) << "\" }" << endl;
    exit(1);
}

bool load_grammar_for_derivation(const string& path, Grammar& g) {
    ifstream in(path);
    if (!in.is_open()) return false;
    string line;
    while (getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto arrow = line.find("->");
        if (arrow == string::npos) continue;
        string lhs = trim(line.substr(0, arrow));
        string rhs = trim(line.substr(arrow + 2));
        bool is_terminal_label = false;
        if (lhs.size() >= 2 && lhs[0] == 'T' && lhs.find(" ") == string::npos) {
            is_terminal_label = true;
            for (size_t i = 1; i < lhs.size(); ++i) {
                if (!std::isdigit(static_cast<unsigned char>(lhs[i]))) {
                    is_terminal_label = false;
                    break;
                }
            }
        }
        if (is_terminal_label) {
            g.terminals[lhs] = rhs;
        } else {
            stringstream ss(rhs);
            string segment;
            while (getline(ss, segment, '|')) {
                segment = trim(segment);
                stringstream ss2(segment);
                string token;
                vector<string> prod;
                while (ss2 >> token) {
                    prod.push_back(token);
                }
                g.productions[lhs].push_back(prod);
            }
        }
    }
    return true;
}

bool load_dot_dfa(const string& path, GrammarDFA& out, string& err) {
    ifstream in(path);
    if (!in.is_open()) {
        err = "Failed to open DOT file: " + path;
        return false;
    }

    string line;
    string start_node_name;

    while (getline(in, line)) {
        // Trim
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        if (line.find("__start ->") == 0) {
            size_t arrow = line.find("->");
            size_t semi = line.find(";");
            if (arrow != string::npos && semi != string::npos) {
                start_node_name = line.substr(arrow + 2, semi - (arrow + 2));
                start_node_name.erase(0, start_node_name.find_first_not_of(" \t"));
                start_node_name.erase(start_node_name.find_last_not_of(" \t") + 1);
            }
        } else if (line.find("->") != string::npos) {
            if (line.find("__start") == 0) continue;
            size_t arrow = line.find("->");
            size_t bracket = line.find("[");
            size_t label_pos = line.find("label=\"");
            if (arrow != string::npos && bracket != string::npos && label_pos != string::npos) {
                string src = line.substr(0, arrow);
                string tgt = line.substr(arrow + 2, bracket - (arrow + 2));
                src.erase(0, src.find_first_not_of(" \t"));
                src.erase(src.find_last_not_of(" \t") + 1);
                tgt.erase(0, tgt.find_first_not_of(" \t"));
                tgt.erase(tgt.find_last_not_of(" \t") + 1);
                size_t label_end = line.find("\"", label_pos + 7);
                string lbl = line.substr(label_pos + 7, label_end - (label_pos + 7));
                out.add_transition(src, lbl, tgt);
            }
        } else if (line.find("[") != string::npos && line.find("label=") != string::npos) {
            if (line.find("__start") == 0) continue;
            if (line.find("node [") == 0) continue;
            size_t bracket = line.find("[");
            string id = line.substr(0, bracket);
            id.erase(0, id.find_first_not_of(" \t"));
            id.erase(id.find_last_not_of(" \t") + 1);
            bool is_accepting = line.find("doublecircle") != string::npos;
            if (is_accepting) {
                out.set_accepting(id);
            } else {
                out.add_state_if_missing(id);
            }
        }
    }

    if (!start_node_name.empty()) {
        out.set_start(start_node_name);
    } else if (!out.names.empty()) {
        if (out.idx.count("S")) out.set_start("S");
        else out.start = 0;
    }

    return true;
}

size_t PDA::get_or_add_state(const string& name) {
    if (state_map.find(name) == state_map.end()) {
        state_map[name] = states.size();
        states.push_back(PDAState{name, false, {}});
    }
    return state_map[name];
}

bool load_dot_pda(const string& path, PDA& out, string& err) {
    ifstream in(path);
    if (!in.is_open()) {
        err = "Failed to open DOT file: " + path;
        return false;
    }

    string line;
    string start_node_name;

    while (getline(in, line)) {
        line = trim(line);
        if (line.empty()) continue;
        if (line.find("__start ->") == 0) {
             size_t arrow = line.find("->");
             size_t bracket = line.find("[");
             size_t semi = line.find(";");
             if (arrow != string::npos) {
                 size_t end_name = (bracket != string::npos) ? bracket : semi;
                 string target_name = trim(line.substr(arrow + 2, end_name - (arrow + 2)));
                 start_node_name = target_name;
                 // If the __start edge carries a label, create a real __start
                 // state and add the transition from it. This restores the
                 // previous behavior where __start can bootstrap the stack
                 // (for example, pushing Z0).
                 if (bracket != string::npos && line.find("label=") != string::npos) {
                     size_t src_idx = out.get_or_add_state("__start");
                     out.start = src_idx;
                     size_t label_pos = line.find("label=\"");
                     if (label_pos != string::npos) {
                         size_t label_end = line.find("\"", label_pos + 7);
                         string lbl = line.substr(label_pos + 7, label_end - (label_pos + 7));
                         string input_sym = "ε";
                         string pop_sym = "ε";
                         vector<string> push_syms;
                         size_t comma = lbl.find(",");
                         size_t arrow_lbl = lbl.find("->");
                         if (comma != string::npos && arrow_lbl != string::npos) {
                             input_sym = trim(lbl.substr(0, comma));
                             pop_sym = trim(lbl.substr(comma + 1, arrow_lbl - (comma + 1)));
                             string push_str = trim(lbl.substr(arrow_lbl + 2));
                             if (push_str != "ε") {
                                 stringstream ss(push_str);
                                 string s;
                                 while (ss >> s) push_syms.push_back(s);
                             }
                         } else {
                             input_sym = lbl;
                         }
                         size_t tgt_idx = out.get_or_add_state(target_name);
                         out.states[src_idx].transitions.push_back({input_sym, pop_sym, push_syms, tgt_idx});
                     }
                 }
             }
        } else if (line.find("->") != string::npos) {
            if (line.find("__start") == 0) {
                 continue;
            }
            size_t arrow = line.find("->");
            size_t bracket = line.find("[");
            size_t label_pos = line.find("label=\"");
            if (arrow != string::npos && bracket != string::npos && label_pos != string::npos) {
                string src = trim(line.substr(0, arrow));
                string tgt = trim(line.substr(arrow + 2, bracket - (arrow + 2)));
                size_t label_end = line.find("\"", label_pos + 7);
                string lbl = line.substr(label_pos + 7, label_end - (label_pos + 7));
                string input_sym = "ε";
                string pop_sym = "ε";
                vector<string> push_syms;
                size_t comma = lbl.find(",");
                size_t arrow_lbl = lbl.find("->");
                if (comma != string::npos && arrow_lbl != string::npos) {
                    input_sym = trim(lbl.substr(0, comma));
                    pop_sym = trim(lbl.substr(comma + 1, arrow_lbl - (comma + 1)));
                    string push_str = trim(lbl.substr(arrow_lbl + 2));
                    if (push_str != "ε") {
                        stringstream ss(push_str);
                        string s;
                        while (ss >> s) push_syms.push_back(s);
                    }
                } else {
                    input_sym = lbl;
                }
                size_t src_idx = out.get_or_add_state(src);
                size_t tgt_idx = out.get_or_add_state(tgt);
                out.states[src_idx].transitions.push_back({input_sym, pop_sym, push_syms, tgt_idx});
            }
        } else if (line.find("[") != string::npos && line.find("label=") != string::npos) {
            if (line.find("__start") == 0) continue;
            if (line.find("node [") == 0) continue;
            size_t bracket = line.find("[");
            string id = trim(line.substr(0, bracket));
            size_t idx = out.get_or_add_state(id);
            if (line.find("doublecircle") != string::npos) {
                out.states[idx].accepting = true;
            }
        }
    }

    if (!start_node_name.empty() && out.state_map.count(start_node_name)) {
        if (out.states.empty() || out.states[out.start].name != "__start") {
             out.start = out.state_map[start_node_name];
        }
    }
    return true;

}
}
