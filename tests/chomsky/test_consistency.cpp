#include <iostream>
#include <string>
#include <sstream>

#include "automata/pta.hpp"
#include "automata/dfa.hpp"
#include "utils/dataset.hpp"

using namespace automata_security;

int main() {
    // sequences that create branching after 'a'
    LabeledSequence s1; s1.id = "s1"; s1.symbols = {"a", "b"}; s1.label = true;
    LabeledSequence s2; s2.id = "s2"; s2.symbols = {"a", "c"}; s2.label = false;
    LabeledSequence s3; s3.id = "s3"; s3.symbols = {"d"}; s3.label = true;

    std::vector<LabeledSequence> samples = {s1, s2, s3};

    PTA pta; pta.build(samples);
    DFA dfa = DFA::from_pta(pta).minimize();
    std::string grammar = dfa.to_chomsky();

    // Terminals should include a,b,c,d
    for (const auto& t : {"a", "b", "c", "d"}) {
        if (grammar.find(t) == std::string::npos) {
            std::cerr << "Expected terminal '" << t << "' not found in grammar\n";
            return 1;
        }
    }

    // Find Tn nonterminals that map to terminals 'b' and 'c'
    std::string T_b;
    std::string T_c;
    std::istringstream in(grammar);
    std::string line;
    while (std::getline(in, line)) {
        // match lines like: "  T1 -> b" or "  T2 -> \"hello world\""
        auto arrow = line.find("->");
        if (arrow == std::string::npos) continue;
        auto lhs = line.substr(0, arrow);
        auto rhs = line.substr(arrow+2);
        // trim
    auto lfirst = lhs.find_first_not_of(" \t");
    if (lfirst == std::string::npos) continue;
    lhs = lhs.substr(lfirst);
    auto lend = lhs.find_last_not_of(" \t");
    if (lend != std::string::npos) lhs = lhs.substr(0, lend + 1);
        auto rfirst = rhs.find_first_not_of(" \t");
        if (rfirst == std::string::npos) continue;
        rhs = rhs.substr(rfirst);
        if (lhs.rfind("T", 0) == 0) {
            if (rhs == "b") T_b = lhs;
            if (rhs == "c") T_c = lhs;
        }
    }

    if (T_b.empty() || T_c.empty()) {
        std::cerr << "Could not find terminal helper nonterminals for b/c\n";
        std::cerr << "Grammar:\n" << grammar << "\n";
        return 1;
    }

    // Now check there is a binary production containing T_b and some nonterminal
    if (grammar.find(T_b + " ") == std::string::npos) {
        std::cerr << "Expected production using " << T_b << " not found\n";
        std::cerr << "Grammar:\n" << grammar << "\n";
        return 1;
    }
    if (grammar.find(T_c + " ") == std::string::npos) {
        std::cerr << "Expected production using " << T_c << " not found\n";
        std::cerr << "Grammar:\n" << grammar << "\n";
        return 1;
    }

    std::cout << "test_chomsky_consistency: PASS\n";
    return 0;
}
