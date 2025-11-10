#pragma once

#include <cstddef>
#include <vector>

#include "automata/dfa.hpp"
#include "utils/dataset.hpp"

namespace automata_security {

struct Metrics {
    double accuracy{0.0};
    double false_positive_rate{0.0};
    double false_negative_rate{0.0};
    std::size_t states_before{0};
    std::size_t states_after{0};
    double minimization_ms{0.0};
};

Metrics evaluate(const DFA& dfa,
                 const std::vector<LabeledSequence>& test_sequences);

}  // namespace automata_security
