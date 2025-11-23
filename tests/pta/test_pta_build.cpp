#include <iostream>
#include <vector>

#include "automata/pta.hpp"
#include "utils/dataset.hpp"

using namespace automata_security;

int main() {
    LabeledSequence s1;
    s1.id = "s1";
    s1.symbols = {"a", "b"};
    s1.label = true;

    LabeledSequence s2;
    s2.id = "s2";
    s2.symbols = {"a", "c"};
    s2.label = false;

    std::vector<LabeledSequence> samples = {s1, s2};

    PTA pta;
    pta.build(samples);

    const auto& nodes = pta.nodes();
    // Expect at least root + two children for the two different continuations
    if (nodes.size() < 3) {
        std::cerr << "PTA nodes too few: " << nodes.size() << "\n";
        return 1;
    }

    // root transitions should contain "a"
    const auto& root = nodes[pta.start_state()];
    if (!root.transitions.count("a")) {
        std::cerr << "PTA root missing transition on 'a'\n";
        return 1;
    }

    std::cout << "test_pta_build: PASS\n";
    return 0;
}
