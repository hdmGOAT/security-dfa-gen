#include <iostream>
#include <vector>

#include "automata/pta.hpp"
#include "automata/dfa.hpp"
#include "evaluator.hpp"
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

    auto metrics = evaluate(dfa, samples);

    if (metrics.accuracy < 0.9999 || metrics.accuracy > 1.0001) {
        std::cerr << "Expected accuracy 1.0 got " << metrics.accuracy << "\n";
        return 1;
    }

    if (metrics.false_positive_rate != 0.0 || metrics.false_negative_rate != 0.0) {
        std::cerr << "Expected zero false rates got fp=" << metrics.false_positive_rate
                  << " fn=" << metrics.false_negative_rate << "\n";
        return 1;
    }

    std::cout << "test_evaluate: PASS\n";
    return 0;
}
