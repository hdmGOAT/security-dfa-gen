#include "automata/pta.hpp"
#include <stdexcept>
#include <cassert>

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
    // Rebuild PTA from scratch: clear existing nodes and create root
    nodes_.clear();
    ensure_root();

    // For each labeled sequence, walk (or grow) the trie according to symbols
    // encountered. Each symbol corresponds to an edge labeled with the token
    // (e.g. `proto=tcp`). The node reached after consuming all symbols of the
    // sequence is updated with positive/negative counts depending on the label.
    for (const auto& sample : samples) {
        std::size_t current = start_state_;
        // basic invariant: current must always be a valid node index
        assert(current < nodes_.size());

        for (const auto& symbol : sample.symbols) {
            // Ensure current is valid before accessing its transitions
            assert(current < nodes_.size());

            // If the transition for this symbol doesn't exist, create a new node
            // and wire the edge from `current` to the new child.
            auto it = nodes_[current].transitions.find(symbol);
            if (it == nodes_[current].transitions.end()) {
                std::size_t child_id = add_node();
                // add_node() should append a node and return a valid id
                assert(child_id < nodes_.size());
                nodes_[current].transitions.emplace(symbol, child_id);
                current = child_id;
            } else {
                // Reuse existing branch in the trie
                assert(it->second < nodes_.size());
                current = it->second;
            }
        }

        // Update leaf counts: positive_count for labelled-positive samples,
        // negative_count otherwise. These counts are later used to mark
        // accepting/rejecting behavior when converting to DFA.
        if (sample.label) {
            nodes_[current].positive_count += 1;
        } else {
            nodes_[current].negative_count += 1;
        }
    }
}

}  // namespace automata_security
