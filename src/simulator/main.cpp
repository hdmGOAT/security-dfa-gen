#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "project_config.hpp"
#include "utils/parser.hpp"

using namespace automata_security;

static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

struct GrammarDFA {
    std::vector<std::string> names; // index -> name
    std::unordered_map<std::string, std::size_t> idx;
    std::vector<std::unordered_map<std::string, std::size_t>> trans;
    std::vector<bool> accepting;
    std::size_t start{0};

    void add_state_if_missing(const std::string& name) {
        if (idx.find(name) != idx.end()) return;
        std::size_t id = names.size();
        names.push_back(name);
        idx[name] = id;
        trans.emplace_back();
        accepting.push_back(false);
    }

    void set_start(const std::string& name) {
        add_state_if_missing(name);
        start = idx[name];
    }

    void set_accepting(const std::string& name) {
        add_state_if_missing(name);
        accepting[idx[name]] = true;
    }

    void add_transition(const std::string& from, const std::string& on, const std::string& to) {
        add_state_if_missing(from);
        add_state_if_missing(to);
        trans[idx[from]][on] = idx[to];
    }

    // Classify sequence and return (accepted, optional reason for rejection)
    std::pair<bool, std::string> classify_with_reason(const std::vector<std::string>& seq) const {
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
};

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
            nonterminals.insert(lhs);
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
        if (!atom.empty() && atom[0] == 'T') {
            auto it = T_to_term.find(atom);
            if (it != T_to_term.end()) {
                // a production lhs -> Tn   means lhs accepts terminal it->second
                out.set_accepting(lhs);
                // We don't create a terminal-only transition here; the binary rules create transitions
            } else {
                // Unknown Tn — mark non-accepting but keep going
            }
        } else {
            // direct terminal: mark lhs accepting
            out.set_accepting(lhs);
        }
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

struct PDAResult {
    bool ok{true};
    std::string reason;
};

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

int main(int argc, char** argv) {
    std::string grammar_path = "grammar.txt";
    std::string dataset_path;
    size_t threshold = 5;
    bool print_details = false;
    std::string output_path;
    std::string threshold_file;
    std::unordered_map<std::string, size_t> per_host_threshold;
    std::string aggregate_mode = "orig"; // orig | resp | union | uid

    for (int i = 1; i < argc; ++i) {
        std::string a(argv[i]);
        if (a.rfind("--grammar=", 0) == 0) grammar_path = a.substr(10);
        else if (a.rfind("--input=", 0) == 0) dataset_path = a.substr(8);
    else if (a.rfind("--threshold=", 0) == 0) threshold = static_cast<size_t>(std::stoul(a.substr(12)));
    else if (a.rfind("--output=", 0) == 0) output_path = a.substr(9);
    else if (a.rfind("--threshold-file=", 0) == 0) threshold_file = a.substr(17);
    else if (a.rfind("--aggregate=", 0) == 0) aggregate_mode = a.substr(12);
    else if (a == "--details") print_details = true;
        else if (a == "--help" || a == "-h") {
            std::cout << "Usage: simulator --grammar=FILE [--input=FILE] [--threshold=N] [--aggregate=orig|resp|union|uid] [--details]\n";
            return 0;
        }
    }

    if (dataset_path.empty()) dataset_path = kDefaultIotDataset;

    GrammarDFA gdfa;
    std::string err;
    if (!load_cnf_grammar(grammar_path, gdfa, err)) {
        std::cerr << "Failed to load grammar: " << err << "\n";
        return 2;
    }

    // load per-host threshold overrides if provided
    if (!threshold_file.empty()) {
        std::ifstream tf(threshold_file);
        if (!tf.is_open()) {
            std::cerr << "Warning: failed to open threshold file: " << threshold_file << "\n";
        } else {
            std::string line;
            while (std::getline(tf, line)) {
                line = trim(line);
                if (line.empty() || line.rfind("#", 0) == 0) continue;
                // accept formats: host,threshold  or host threshold
                std::string host;
                std::string thr;
                auto comma = line.find(',');
                if (comma != std::string::npos) {
                    host = trim(line.substr(0, comma));
                    thr = trim(line.substr(comma + 1));
                } else {
                    std::istringstream iss(line);
                    iss >> host >> thr;
                }
                if (!host.empty() && !thr.empty()) {
                    try {
                        size_t t = static_cast<size_t>(std::stoul(thr));
                        per_host_threshold[host] = t;
                    } catch (...) {
                        std::cerr << "Warning: invalid threshold for host '" << host << "' in file" << "\n";
                    }
                }
            }
        }
    }

    auto samples = Parser::load_iot_csv(dataset_path);
    if (samples.empty()) {
        std::cerr << "No samples loaded from " << dataset_path << "\n";
        return 1;
    }

    // Aggregate per host according to aggregate_mode
    // supported modes: orig (default), resp, union (associate sample with both orig and resp), uid
    std::unordered_map<std::string, std::vector<std::pair<double, size_t>>> host_index_ts;
    for (size_t i = 0; i < samples.size(); ++i) {
        const auto& s = samples[i];
        if (aggregate_mode == "resp") {
            const std::string key = (!s.resp_host.empty()) ? s.resp_host : (s.host.empty() ? s.id : s.host);
            host_index_ts[key].emplace_back(s.ts, i);
        } else if (aggregate_mode == "union") {
            // add to origin
            const std::string keyo = (!s.host.empty()) ? s.host : s.id;
            host_index_ts[keyo].emplace_back(s.ts, i);
            // add to responder if present and different
            if (!s.resp_host.empty() && s.resp_host != keyo) {
                host_index_ts[s.resp_host].emplace_back(s.ts, i);
            }
        } else if (aggregate_mode == "uid") {
            const std::string key = (!s.uid.empty()) ? s.uid : ((!s.host.empty()) ? s.host : s.id);
            host_index_ts[key].emplace_back(s.ts, i);
        } else {
            // default orig
            const std::string& key = s.host.empty() ? s.id : s.host;
            host_index_ts[key].emplace_back(s.ts, i);
        }
    }
    // sort per-host by timestamp
    std::unordered_map<std::string, std::vector<size_t>> host_sample_indexes;
    for (auto& kv : host_index_ts) {
        auto& vec = kv.second;
        std::sort(vec.begin(), vec.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        auto& outvec = host_sample_indexes[kv.first];
        outvec.reserve(vec.size());
        for (const auto& p : vec) outvec.push_back(p.second);
    }

    struct HostReport {
        size_t malicious_count{0};
        std::vector<std::pair<std::string,std::string>> sample_reasons; // sample id -> reason (accepted/ rejection reason)
        PDAResult pda_result;
    };

    std::unordered_map<std::string, HostReport> reports;

    // classify per-sample using gdfa
    for (const auto& [host, idxs] : host_sample_indexes) {
        HostReport hr;
        for (auto idx : idxs) {
            const auto& s = samples[idx];
            auto [ok, reason] = gdfa.classify_with_reason(s.symbols);
            if (ok) {
                hr.malicious_count++;
            }
            hr.sample_reasons.emplace_back(s.id, reason);
        }
        // build aggregated conn_state sequence for PDA
        std::vector<std::string> conn_seq;
        for (auto idx : idxs) {
            const auto& s = samples[idx];
            for (const auto& sym : s.symbols) {
                if (sym.rfind("state=", 0) == 0) conn_seq.push_back(sym);
            }
        }
        hr.pda_result = validate_pda_sequence(conn_seq);
        reports[host] = std::move(hr);
    }

    // Output summary
    // Prepare output file if requested
    std::ofstream out;
    if (!output_path.empty()) {
        out.open(output_path);
        if (!out.is_open()) {
            std::cerr << "Warning: failed to open output file: " << output_path << "\n";
        } else {
            out << "host,status,malicious_count,blocked,pda_ok,pda_reason\n";
        }
    }

    for (const auto& [host, rep] : reports) {
        size_t host_thresh = threshold;
        auto it_thr = per_host_threshold.find(host);
        if (it_thr != per_host_threshold.end()) host_thresh = it_thr->second;
        bool blocked = rep.malicious_count >= host_thresh;
        if (blocked) {
            std::cout << host << ": BLOCKED (" << rep.malicious_count << " malicious sequences)\n";
            if (out.is_open()) {
                out << host << ",BLOCKED," << rep.malicious_count << ",true," << (rep.pda_result.ok ? "true" : "false") << "," << rep.pda_result.reason << "\n";
            }
            if (print_details) {
                size_t shown = 0;
                for (const auto& pr : rep.sample_reasons) {
                    if (pr.second == "accepted") {
                        std::cout << "    sample " << pr.first << ": accepted by DFA" << "\n";
                        if (++shown >= 10) break;
                    }
                }
            }
            continue;
        }

        if (!rep.pda_result.ok) {
            std::cout << host << ": PDA_REJECTED (" << rep.pda_result.reason << ")" << "\n";
            if (out.is_open()) {
                out << host << ",PDA_REJECTED," << rep.malicious_count << ",false," << (rep.pda_result.ok ? "true" : "false") << "," << rep.pda_result.reason << "\n";
            }
            if (print_details) {
                std::cout << "    malicious_count=" << rep.malicious_count << "\n";
                size_t i = 0;
                for (const auto& pr : rep.sample_reasons) {
                    std::cout << "    sample " << pr.first << ": " << pr.second << "\n";
                    if (++i >= 10) break;
                }
            }
            continue;
        }

        // OK
        std::cout << host << ": OK";
        if (rep.malicious_count > 0) std::cout << " (" << rep.malicious_count << " suspicious sequences)";
        std::cout << "\n";
        if (out.is_open()) {
            out << host << ",OK," << rep.malicious_count << ",false," << (rep.pda_result.ok ? "true" : "false") << "," << rep.pda_result.reason << "\n";
        }
        if (print_details && rep.malicious_count > 0) {
            size_t i = 0;
            for (const auto& pr : rep.sample_reasons) {
                if (pr.second == "accepted") {
                    std::cout << "    sample " << pr.first << ": accepted by DFA" << "\n";
                    if (++i >= 10) break;
                }
            }
        }
    }

    if (out.is_open()) out.close();
    return 0;
}
