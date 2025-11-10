#include "automata/pta.hpp"

#include <stdexcept>

namespace automata_security {

PTA::PTA() : start_state_(0) {
    ensure_root();
}

std::size_t PTA::ensure_root() {
    if (nodes_.empty()) {
        Node root;
        root.id = 0;
        nodes_.push_back(std::move(root));
    }
    start_state_ = 0;
    return start_state_;
}

std::size_t PTA::add_node() {
    Node node;
    node.id = nodes_.size();
    nodes_.push_back(std::move(node));
    return nodes_.back().id;
}

void PTA::build(const std::vector<LabeledSequence>& samples) {
    nodes_.clear();
    ensure_root();

    for (const auto& sample : samples) {
        std::size_t current = start_state_;
        for (const auto& symbol : sample.symbols) {
            auto it = nodes_[current].transitions.find(symbol);
            if (it == nodes_[current].transitions.end()) {
                std::size_t child_id = add_node();
                nodes_[current].transitions.emplace(symbol, child_id);
                current = child_id;
            } else {
                current = it->second;
            }
        }

        if (sample.label) {
            nodes_[current].positive_count += 1;
        } else {
            nodes_[current].negative_count += 1;
        }
    }
}

}  // namespace automata_security
