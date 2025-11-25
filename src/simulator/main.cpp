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
#include "simulator/core.hpp"

using namespace automata_security;

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
