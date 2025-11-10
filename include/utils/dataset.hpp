#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace automata_security {

struct LabeledSequence {
    std::string id;                          // sample identifier (hash, flow id, etc.)
    std::vector<std::string> symbols;        // sequence over finite alphabet
    bool label;                              // true = malicious, false = benign
};

struct DatasetSplit {
    std::vector<LabeledSequence> train;
    std::vector<LabeledSequence> test;
};

}  // namespace automata_security
