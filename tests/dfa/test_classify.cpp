#include <iostream>
#include <vector>

#include "automata/pta.hpp"
#include "automata/dfa.hpp"
#include "utils/dataset.hpp"

using namespace automata_security;

int main() {
    LabeledSequence s1;
    s1.id = "m1";
    s1.symbols = {"x"};
    s1.label = true;

    LabeledSequence s2;
    s2.id = "b1";
    s2.symbols = {"y"};
    s2.label = false;

    std::vector<LabeledSequence> samples = {s1, s2};

    PTA pta;
    pta.build(samples);

    DFA dfa = DFA::from_pta(pta);
    dfa = dfa.minimize();

    bool pred1 = dfa.classify(s1.symbols);
    bool pred2 = dfa.classify(s2.symbols);

    if (pred1 != s1.label) {
        std::cerr << "Classification mismatch for s1: expected " << s1.label << " got " << pred1 << "\n";
        return 1;
    }
    if (pred2 != s2.label) {
        std::cerr << "Classification mismatch for s2: expected " << s2.label << " got " << pred2 << "\n";
        return 1;
    }

    std::cout << "test_classify: PASS\n";
    return 0;
}
