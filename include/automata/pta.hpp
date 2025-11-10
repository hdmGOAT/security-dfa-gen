#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "utils/dataset.hpp"

namespace automata_security {

class PTA {
public:
    struct Node {
        std::size_t id;
        std::unordered_map<std::string, std::size_t> transitions;
        std::size_t positive_count{0};
        std::size_t negative_count{0};
    };

    PTA();

    void build(const std::vector<LabeledSequence>& samples);

    const std::vector<Node>& nodes() const { return nodes_; }
    std::size_t start_state() const { return start_state_; }

private:
    std::size_t start_state_;
    std::vector<Node> nodes_;

    std::size_t ensure_root();
    std::size_t add_node();
};

}  // namespace automata_security
