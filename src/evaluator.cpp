#include "evaluator.hpp"

namespace automata_security {

Metrics evaluate(const DFA& dfa,
                 const std::vector<LabeledSequence>& test_sequences) {
    Metrics metrics;
    if (test_sequences.empty()) {
        return metrics;
    }

    std::size_t true_positive = 0;
    std::size_t true_negative = 0;
    std::size_t false_positive = 0;
    std::size_t false_negative = 0;

    for (const auto& sample : test_sequences) {
        // Classify each test sequence with the DFA and update confusion counts
        // used to compute accuracy, false positive rate and false negative rate.
        bool predicted = dfa.classify(sample.symbols);
        bool actual = sample.label;

        if (predicted && actual) {
            ++true_positive;
        } else if (!predicted && !actual) {
            ++true_negative;
        } else if (predicted && !actual) {
            ++false_positive;
        } else {
            ++false_negative;
        }
    }

    // Compute aggregate metrics. Accuracy is straightforward: fraction of
    // correctly predicted samples. False positive/negative rates are defined
    // relative to their respective conditionals to avoid division by zero.
    const double total = static_cast<double>(test_sequences.size());
    metrics.accuracy = (true_positive + true_negative) / total;

    const double fp_denom = static_cast<double>(false_positive + true_negative);
    const double fn_denom = static_cast<double>(false_negative + true_positive);
    // If denominators are zero (no negatives/positives in the test set), we
    // return 0.0 to indicate the rate is undefined in that slice rather than
    // producing NaN or inf.
    metrics.false_positive_rate = fp_denom > 0.0 ? false_positive / fp_denom : 0.0;
    metrics.false_negative_rate = fn_denom > 0.0 ? false_negative / fn_denom : 0.0;

    return metrics;
}

}  // namespace automata_security


