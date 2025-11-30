#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "automata/dfa.hpp"
#include "automata/pta.hpp"
#include "evaluator.hpp"
#include "project_config.hpp"
#include "utils/parser.hpp"

namespace automata_security {
namespace {

struct CommandLineOptions {
    std::vector<std::string> input_paths;
    std::vector<std::string> test_paths;
    std::string export_dot_path;
    std::string export_definition_path;
    std::string export_grammar_path;
    double train_ratio{kDefaultTrainRatio};
    unsigned int seed{42U};
    bool train_full{false};
    bool print_definition{false};
};

struct FeatureSummary {
    std::size_t unique_count{0};
    std::vector<std::string> sample_features;
    bool truncated{false};
};

void print_usage(const char* program) {
    std::cout << "Usage: " << program
              << " [--input=FILE] [--train-ratio=0.7]"
                 " [--seed=42] [--export-dot=automaton.dot]\n";
    std::cout << "Options:\n"
              << "  --input=FILE        Override IoT dataset file path (repeatable).\n"
                  << "  --train-ratio=VAL   Train/test split ratio (0 < VAL < 1).\n"
                  << "  --train-full        Train on entire dataset (ignore split).\n"
                  << "  --test=FILE         Additional dataset file to evaluate on." \
                      " (repeatable)\n"
                  << "  --export-definition=FILE  Write DFA formal definition to FILE.\n"
                  << "  --export-grammar=FILE     Write Chomsky Normal Form (CNF) grammar to FILE.\n"
                  << "                           (produces CNF with helper nonterminals Tn -> a)\n"
                  << "  --print-definition  Print DFA formal definition to stdout.\n"
              << "  --seed=NUM          Random seed for the train/test shuffle.\n"
              << "  --export-dot=FILE   Export minimized DFA to DOT file.\n"
              << "  --version           Print version information.\n"
              << "  --help              Show this message.\n";
}

bool parse_argument(const std::string& arg,
                    CommandLineOptions& opts,
                    const char* program) {
    if (arg == "--help" || arg == "-h") {
        print_usage(program);
        std::exit(0);
    }
    if (arg == "--version") {
        std::cout << "automata-security " << kVersion << "\n";
        std::exit(0);
    }

    auto parse_key_value = [](const std::string& option,
                              const std::string& prefix) -> std::optional<std::string> {
        if (option.rfind(prefix, 0) == 0) {
            return option.substr(prefix.size());
        }
        return std::nullopt;
    };

    if (auto value = parse_key_value(arg, "--input=")) {
        opts.input_paths.push_back(*value);
        return true;
    }
    if (auto value = parse_key_value(arg, "--train-ratio=")) {
        opts.train_ratio = std::stod(*value);
        return true;
    }
    if (auto value = parse_key_value(arg, "--seed=")) {
        opts.seed = static_cast<unsigned int>(std::stoul(*value));
        return true;
    }
    if (auto value = parse_key_value(arg, "--export-dot=")) {
        opts.export_dot_path = *value;
        return true;
    }
    if (auto value = parse_key_value(arg, "--export-grammar=")) {
        opts.export_grammar_path = *value;
        return true;
    }
    if (auto value = parse_key_value(arg, "--export-definition=")) {
        opts.export_definition_path = *value;
        return true;
    }
    if (arg == "--train-full") {
        opts.train_full = true;
        return true;
    }
    if (arg == "--print-definition") {
        opts.print_definition = true;
        return true;
    }
    if (auto value = parse_key_value(arg, "--test=")) {
        opts.test_paths.push_back(*value);
        return true;
    }

    std::cerr << "Unknown option: " << arg << "\n";
    print_usage(program);
    return false;
}

std::vector<LabeledSequence> load_dataset(const CommandLineOptions& opts,
                                          const std::string& path) {
    (void)opts;
    return Parser::load_iot_csv(path);
}

struct EvaluationResult {
    std::string source_path;
    Metrics metrics;
    std::size_t test_size{0};
};

void export_dot_if_requested(const DFA& dfa, const std::string& path) {
    if (path.empty()) {
        return;
    }

    std::ofstream output(path);
    if (!output.is_open()) {
        throw std::runtime_error("Failed to open DOT output file: " + path);
    }

    output << dfa.to_dot();
}

void export_grammar_if_requested(const DFA& dfa, const std::string& path) {
    if (path.empty()) {
        return;
    }

    std::ofstream output(path);
    if (!output.is_open()) {
        throw std::runtime_error("Failed to open grammar output file: " + path);
    }

    output << dfa.to_chomsky();
}

FeatureSummary summarize_features(const std::vector<LabeledSequence>& samples,
                                  std::size_t max_display = 20) {
    FeatureSummary summary;
    if (samples.empty()) {
        return summary;
    }

    std::unordered_set<std::string> unique;
    unique.reserve(256);

    for (const auto& sample : samples) {
        for (const auto& symbol : sample.symbols) {
            unique.insert(symbol);
        }
    }

    summary.unique_count = unique.size();

    std::vector<std::string> sorted(unique.begin(), unique.end());
    std::sort(sorted.begin(), sorted.end());

    if (sorted.size() > max_display) {
        summary.sample_features.assign(sorted.begin(), sorted.begin() + max_display);
        summary.truncated = true;
    } else {
        summary.sample_features = std::move(sorted);
    }

    return summary;
}

}  // namespace
}  // namespace automata_security

int main(int argc, char* argv[]) {
    using namespace automata_security;

    CommandLineOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (!parse_argument(arg, options, argv[0])) {
            return 1;
        }
    }

    try {
        if (options.input_paths.empty()) {
            options.input_paths.push_back(kDefaultIotDataset);
        }

        std::vector<LabeledSequence> samples;
        for (const auto& path : options.input_paths) {
            std::cout << "[1/5] Loading IoT dataset from: " << path << std::endl;
            auto current_samples = load_dataset(options, path);
            if (current_samples.empty()) {
                std::cerr << "Warning: No samples loaded from " << path << std::endl;
            } else {
                std::cout << "      Loaded " << current_samples.size() << " sequences." << std::endl;
                samples.insert(samples.end(),
                               std::make_move_iterator(current_samples.begin()),
                               std::make_move_iterator(current_samples.end()));
            }
        }

        if (samples.empty()) {
            std::cerr << "No samples loaded from any input. Check dataset paths and format." << std::endl;
            return 1;
        }
        std::cout << "      Total loaded: " << samples.size() << " sequences." << std::endl;

        auto feature_summary = summarize_features(samples);
        std::cout << "      Features (" << feature_summary.unique_count << " unique): ";
        if (feature_summary.sample_features.empty()) {
            std::cout << "(none)" << std::endl;
        } else {
            bool first = true;
            for (const auto& feature : feature_summary.sample_features) {
                if (!first) {
                    std::cout << ", ";
                }
                std::cout << feature;
                first = false;
            }
            if (feature_summary.truncated) {
                std::cout << ", ...";
            }
            std::cout << std::endl;
        }

        std::vector<LabeledSequence> train_sequences;
        std::vector<LabeledSequence> local_test_sequences;

        if (options.train_full) {
            train_sequences = samples;
            std::cout << "[2/6] Training on entire dataset (" << train_sequences.size()
                      << " sequences)." << std::endl;
        } else {
            std::cout << "[2/6] Splitting dataset with train_ratio=" << options.train_ratio
                      << " and seed=" << options.seed << std::endl;
            auto split = train_test_split(samples, options.train_ratio, options.seed);
            if (split.train.empty() || split.test.empty()) {
                std::cerr << "Train/test split produced empty partition. Adjust train ratio." << std::endl;
                return 1;
            }
            train_sequences = std::move(split.train);
            local_test_sequences = std::move(split.test);
            std::cout << "      Train: " << train_sequences.size()
                      << ", Test: " << local_test_sequences.size() << std::endl;
        }

        std::cout << "[3/6] Building Prefix Tree Acceptor (PTA)..." << std::endl;

        PTA pta;
        pta.build(train_sequences);
        std::cout << "      PTA states: " << pta.nodes().size() << std::endl;

        std::cout << "[4/6] Constructing DFA from PTA and ensuring total transitions..." << std::endl;
        DFA dfa = DFA::from_pta(pta);
        const std::size_t states_before = dfa.states().size();

        std::cout << "      DFA states: " << states_before << std::endl;

        std::cout << "[5/6] Minimizing DFA..." << std::endl;
        const auto minimization_start = std::chrono::steady_clock::now();
        DFA minimized = dfa.minimize();
        const auto minimization_end = std::chrono::steady_clock::now();
        const double minimization_ms =
            std::chrono::duration<double, std::milli>(minimization_end - minimization_start)
                .count();
        dfa = std::move(minimized);
        const std::size_t states_after = dfa.states().size();
        std::cout << "      Minimized DFA states: " << states_after << std::endl;

        if (options.print_definition || !options.export_definition_path.empty()) {
            const auto definition_text = dfa.to_definition();
            if (options.print_definition) {
                std::cout << "\n" << definition_text << std::endl;
            }
            if (!options.export_definition_path.empty()) {
                std::ofstream definition_output(options.export_definition_path);
                if (!definition_output.is_open()) {
                    std::cerr << "Warning: Failed to open definition output file: "
                              << options.export_definition_path << std::endl;
                } else {
                    definition_output << definition_text;
                }
            }
        }

        std::cout << "[6/6] Evaluating DFA on test set..." << std::endl;
        std::vector<EvaluationResult> evaluation_results;

        if (!local_test_sequences.empty()) {
            EvaluationResult result;
            result.source_path = "combined_inputs";
            result.test_size = local_test_sequences.size();
            result.metrics = evaluate(dfa, local_test_sequences);
            result.metrics.states_before = states_before;
            result.metrics.states_after = states_after;
            result.metrics.minimization_ms = minimization_ms;
            evaluation_results.push_back(result);
        }

        for (const auto& test_path : options.test_paths) {
            std::cout << "      Evaluating holdout dataset: " << test_path << std::endl;
            auto holdout_samples = load_dataset(options, test_path);
            if (holdout_samples.empty()) {
                std::cerr << "        Warning: no samples loaded from " << test_path
                          << std::endl;
                continue;
            }

            EvaluationResult result;
            result.source_path = test_path;
            result.test_size = holdout_samples.size();
            result.metrics = evaluate(dfa, holdout_samples);
            result.metrics.states_before = states_before;
            result.metrics.states_after = states_after;
            result.metrics.minimization_ms = minimization_ms;
            evaluation_results.push_back(std::move(result));
        }

        std::cout << std::fixed << std::setprecision(4);
        std::cout << "\nSummary" << std::endl;
        std::cout << "=======" << std::endl;
        std::cout << "Dataset: IoT (Multiple Inputs)\n";
        for (const auto& p : options.input_paths) {
            std::cout << "  Input: " << p << "\n";
        }
        std::cout << "Samples: " << samples.size() << " (train=" << train_sequences.size();
        if (!local_test_sequences.empty()) {
            std::cout << ", test=" << local_test_sequences.size();
        }
        std::cout << ")\n";
        if (!feature_summary.sample_features.empty()) {
            std::cout << "Features (" << feature_summary.unique_count << " unique)";
            if (feature_summary.truncated) {
                std::cout << " [showing first " << feature_summary.sample_features.size()
                          << "]";
            }
            std::cout << ": ";
            bool first = true;
            for (const auto& feature : feature_summary.sample_features) {
                if (!first) {
                    std::cout << ", ";
                }
                std::cout << feature;
                first = false;
            }
            if (feature_summary.truncated) {
                std::cout << ", ...";
            }
            std::cout << "\n";
        } else {
            std::cout << "Features: (none)\n";
        }
        std::cout << "States: before=" << states_before << ", after=" << states_after << "\n";
        std::cout << "Minimization: " << minimization_ms << " ms\n";
        if (!options.export_definition_path.empty()) {
            std::cout << "Definition file: " << options.export_definition_path << "\n";
        }

        for (const auto& result : evaluation_results) {
            std::cout << "\nResults for: " << result.source_path << "\n";
            std::cout << "  Test samples: " << result.test_size << "\n";
            std::cout << "  Accuracy: " << result.metrics.accuracy * 100.0 << "%\n";
            std::cout << "  False Positive Rate: "
                      << result.metrics.false_positive_rate * 100.0 << "%\n";
            std::cout << "  False Negative Rate: "
                      << result.metrics.false_negative_rate * 100.0 << "%\n";
            std::cout << "  States (before -> after): " << result.metrics.states_before
                      << " -> " << result.metrics.states_after << "\n";
            std::cout << "  Minimization time: " << result.metrics.minimization_ms
                      << " ms\n";
        }

        try {
            export_dot_if_requested(dfa, options.export_dot_path);
            try {
                export_grammar_if_requested(dfa, options.export_grammar_path);
            } catch (const std::exception& ex) {
                std::cerr << "Warning: " << ex.what() << std::endl;
            }
        } catch (const std::exception& ex) {
            std::cerr << "Warning: " << ex.what() << std::endl;
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
