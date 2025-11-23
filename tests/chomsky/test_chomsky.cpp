#include <iostream>
#include <string>
#include <sstream>
#include <unordered_set>

#include "automata/pta.hpp"
#include "automata/dfa.hpp"
#include "utils/dataset.hpp"

using namespace automata_security;

int main() {
    // Single sample: sequence ["x"] labeled malicious (true)
    LabeledSequence sample;
    sample.id = "s1";
    sample.symbols = {"x"};
    sample.label = true;

    std::vector<LabeledSequence> samples{sample};

    PTA pta;
    pta.build(samples);

    DFA dfa = DFA::from_pta(pta);
    DFA minimized = dfa.minimize();

    std::string grammar = minimized.to_chomsky();

    // For CNF: ensure there exists a terminal production A -> x and also
    // a binary production A -> N M (two nonterminals) somewhere (reflecting transitions)
    std::istringstream in(grammar);
    std::string line;
    bool found_terminal_x = false;
    bool found_binary = false;

    while (std::getline(in, line)) {
        // trim leading spaces
        auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        std::string trimmed = line.substr(first);
    if (trimmed.rfind("A", 0) != 0 && trimmed.rfind("T", 0) != 0 && trimmed.rfind("S", 0) != 0) continue; // only rules

        auto arrow = trimmed.find("->");
        if (arrow == std::string::npos) continue;
        auto rhs = trimmed.substr(arrow + 2);

        // split alternatives
        size_t pos = 0;
        while (pos < rhs.size()) {
            auto next = rhs.find('|', pos);
            std::string alt = (next == std::string::npos) ? rhs.substr(pos) : rhs.substr(pos, next - pos);
            // trim
            auto a_first = alt.find_first_not_of(" \t");
            if (a_first == std::string::npos) break;
            auto a_last = alt.find_last_not_of(" \t");
            alt = alt.substr(a_first, a_last - a_first + 1);

            // terminal production A -> x
            if (alt == "x") {
                found_terminal_x = true;
            }

            // binary production A -> N M  (two nonterminals, e.g., T0 A1)
            {
                std::istringstream toks(alt);
                std::string t1, t2;
                if (toks >> t1 >> t2) {
                    if (!t1.empty() && !t2.empty() && std::isupper(static_cast<unsigned char>(t1[0])) && std::isupper(static_cast<unsigned char>(t2[0]))) {
                        found_binary = true;
                    }
                }
            }

            if (next == std::string::npos) break;
            pos = next + 1;
        }
    }

    bool pass = found_terminal_x && found_binary;

    if (pass) {
        std::cout << "test_chomsky: PASS\n";
        return 0;
    }

    std::cerr << "Grammar output:\n" << grammar << "\n";
    std::cerr << "test_chomsky: FAIL\n";
    return 1;
}
