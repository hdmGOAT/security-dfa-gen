#pragma once

#include <string>
#include <vector>

#include "utils/dataset.hpp"

namespace automata_security {

class Parser {
public:
    static std::vector<LabeledSequence> load_malware_csv(const std::string& path);
    static std::vector<LabeledSequence> load_iot_csv(const std::string& path);
};

DatasetSplit train_test_split(const std::vector<LabeledSequence>& data,
                              double train_ratio,
                              unsigned int seed = 42U);

}  // namespace automata_security
