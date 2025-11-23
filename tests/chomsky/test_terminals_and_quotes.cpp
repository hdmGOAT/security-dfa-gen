#include <iostream>
#include <string>

#include "automata/pta.hpp"
#include "automata/dfa.hpp"
#include "utils/dataset.hpp"

using namespace automata_security;

int main() {
    LabeledSequence s1;
    s1.id = "t1";
    s1.symbols = {"hello world"};
    s1.label = true;

    LabeledSequence s2;
    s2.id = "t2";
    s2.symbols = {"simple"};
    s2.label = false;

    std::vector<LabeledSequence> samples = {s1, s2};

    PTA pta;
    pta.build(samples);
    DFA dfa = DFA::from_pta(pta).minimize();
    std::string grammar = dfa.to_chomsky();

    // Terminals line should contain quoted "hello world"
    if (grammar.find("\"hello world\"") == std::string::npos) {
        std::cerr << "Expected quoted terminal \"hello world\" not found\n";
        std::cerr << "Grammar:\n" << grammar << "\n";
        return 1;
    }

    // Also expect 'simple' as unquoted terminal
    if (grammar.find("simple") == std::string::npos) {
        std::cerr << "Expected terminal 'simple' not found\n";
        return 1;
    }

    std::cout << "test_chomsky_terminals_and_quotes: PASS\n";
    return 0;
}
