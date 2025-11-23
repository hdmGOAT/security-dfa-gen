#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace automata_security {

struct LabeledSequence {
    std::string id;                          // sample identifier (hash, flow id, etc.)
    std::string host;                        // host identifier (e.g. id.orig_h) when available
    std::string resp_host;                   // responder host identifier (e.g. id.resp_h) when available
    std::string uid;                         // connection/session uid when available
    double ts{0.0};                           // timestamp (seconds since epoch) when available
    std::vector<std::string> symbols;        // sequence over finite alphabet
    bool label;                              // true = malicious, false = benign
};

struct DatasetSplit {
    std::vector<LabeledSequence> train;
    std::vector<LabeledSequence> test;
};

}  // namespace automata_security
