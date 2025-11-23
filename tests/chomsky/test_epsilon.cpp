#include <iostream>
#include <string>
#include <sstream>

#include "automata/pta.hpp"
#include "automata/dfa.hpp"
#include "utils/dataset.hpp"

using namespace automata_security;

int main() {
    // Empty-symbol sequence which is labeled malicious -> start state should be accepting
    LabeledSequence s;
    s.id = "empty";
    s.symbols = {};
    s.label = true;

    std::vector<LabeledSequence> samples = {s};
    PTA pta;
    pta.build(samples);
    DFA dfa = DFA::from_pta(pta).minimize();

    std::string grammar = dfa.to_chomsky();

    // find Start line
    // find Start: line (either 'Start: S' or 'Start: A#')
    std::istringstream in(grammar);
    std::string line;
    std::string start_nt;
    while (std::getline(in, line)) {
        if (line.rfind("Start:", 0) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                start_nt = line.substr(pos + 1);
                // trim
                auto first = start_nt.find_first_not_of(" \t");
                auto last = start_nt.find_last_not_of(" \t");
                if (first != std::string::npos && last != std::string::npos) {
                    start_nt = start_nt.substr(first, last - first + 1);
                }
            }
            break;
        }
    }

    if (start_nt.empty()) {
        std::cerr << "Could not find Start nonterminal in grammar\n";
        std::cerr << "Grammar:\n" << grammar << "\n";
        return 1;
    }

    std::string epsilon_rule = start_nt + " -> ε";
    if (grammar.find(epsilon_rule) == std::string::npos) {
        std::cerr << "Missing epsilon rule for start: " << epsilon_rule << "\n";
        std::cerr << "Grammar:\n" << grammar << "\n";
        return 1;
    }

    std::cout << "test_chomsky_epsilon: PASS\n";
    return 0;
}
