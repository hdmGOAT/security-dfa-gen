#include "utils/parser.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <cassert>

namespace automata_security {
namespace {

void trim_inplace(std::string& value) {
    auto begin = value.begin();
    while (begin != value.end() && std::isspace(static_cast<unsigned char>(*begin))) {
        ++begin;
    }
    auto end = value.end();
    while (end != begin && std::isspace(static_cast<unsigned char>(*(end - 1)))) {
        --end;
    }
    if (begin == value.begin() && end == value.end()) {
        return;
    }
    value.assign(begin, end);
}

std::vector<std::string> parse_delimited_line(const std::string& line,
                                              char delimiter = ',') {
    std::vector<std::string> result;
    std::string current;
    bool in_quotes = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        char ch = line[i];
        if (ch == '"') {
            if (in_quotes && i + 1 < line.size() && line[i + 1] == '"') {
                current.push_back('"');
                ++i;
            } else {
                in_quotes = !in_quotes;
            }
        } else if (ch == delimiter && !in_quotes) {
            trim_inplace(current);
            result.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }

    trim_inplace(current);
    result.push_back(current);
    return result;
}

// parse_delimited_line supports RFC-style CSV quoting: double quotes are
// escaped by doubling them, and delimiters inside quoted regions are ignored.
// This helper returns the list of tokens for a single input line.

std::unordered_map<std::string, std::size_t> header_index(
    const std::vector<std::string>& header) {
    std::unordered_map<std::string, std::size_t> index;
    for (std::size_t i = 0; i < header.size(); ++i) {
        index[header[i]] = i;
    }
    return index;
}

std::string to_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool is_true_label(const std::string& value) {
    auto lowercase = to_lower_copy(value);
    if (lowercase == "1" || lowercase == "true" || lowercase == "malware") {
        return true;
    }
    if (lowercase == "0" || lowercase == "false" || lowercase == "benign") {
        return false;
    }
    return lowercase.find("malic") != std::string::npos;
}

}  // namespace

std::vector<LabeledSequence> Parser::load_malware_csv(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Failed to open malware dataset: " + path);
    }

    std::string line;
    if (!std::getline(input, line)) {
        return {};
    }

    // Parse header line (CSV) into column tokens. This supports RFC-style
    // quoting so fields containing commas will be handled correctly.
    auto header = parse_delimited_line(line);
    auto index = header_index(header);

        // sanity: header index entries should be within header size
        for (const auto& p : index) {
            assert(p.second < header.size());
        }
    auto id_it = index.find("hash");
    auto label_it = index.find("malware");

    if (id_it == index.end() || label_it == index.end()) {
        throw std::runtime_error("Malware dataset missing required columns 'hash' or 'malware'.");
    }

    // sanity checks
    assert(id_it->second < header.size());
    assert(label_it->second < header.size());

    std::vector<std::size_t> sequence_columns;
    for (const auto& [name, col_idx] : index) {
        if (name.size() > 2 && name[0] == 't' && name[1] == '_') {
            sequence_columns.push_back(col_idx);
        }
    }

    std::sort(sequence_columns.begin(), sequence_columns.end());

    std::vector<LabeledSequence> samples;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }

    auto tokens = parse_delimited_line(line);
        if (tokens.size() <= label_it->second) {
            continue;
        }

        LabeledSequence sample;
        sample.id = tokens[id_it->second];
        sample.label = is_true_label(tokens[label_it->second]);

        for (auto col : sequence_columns) {
            if (col < tokens.size()) {
                const auto& value = tokens[col];
                if (!value.empty()) {
                    sample.symbols.push_back(value);
                }
            }
        }

        // Only keep sequences that had at least one symbol token extracted.
        if (!sample.symbols.empty()) {
            samples.push_back(std::move(sample));
        }
    }

    return samples;
}

std::vector<LabeledSequence> Parser::load_iot_csv(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Failed to open IoT dataset: " + path);
    }

    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line[0] == '#') {
            continue;
        }
        if (!line.empty()) {
            break;
        }
    }

    if (line.empty()) {
        return {};
    }

    // Detect delimiter: some datasets use '|' while others use ','. We
    // inspect the header line to choose an appropriate separator for parsing.
    char delimiter = line.find('|') != std::string::npos ? '|' : ',';
    auto header = parse_delimited_line(line, delimiter);
    auto index = header_index(header);

    auto label_it = index.find("label");
    if (label_it == index.end()) {
        throw std::runtime_error("IoT dataset missing required column 'label'.");
    }

    assert(label_it->second < header.size());

    std::size_t detailed_label_col = index.count("detailed-label")
                                         ? index["detailed-label"]
                                         : header.size();

    std::size_t proto_col = index.count("proto") ? index["proto"] : header.size();
    std::size_t conn_state_col = index.count("conn_state") ? index["conn_state"] : header.size();
    std::size_t service_col = index.count("service") ? index["service"] : header.size();
    std::size_t id_orig_h_col = index.count("id.orig_h") ? index["id.orig_h"] : header.size();
    std::size_t id_resp_h_col = index.count("id.resp_h") ? index["id.resp_h"] : header.size();
    std::size_t uid_col = index.count("uid") ? index["uid"] : header.size();
    std::size_t ts_col = index.count("ts") ? index["ts"] : header.size();

    std::vector<LabeledSequence> samples;
    std::size_t line_number = 1;  // include header
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty() || line[0] == '#') {
            continue;
        }

    // Tokenize the row using the detected delimiter. Supports quoted fields
    // so embedded delimiters or quotes are handled safely.
    auto tokens = parse_delimited_line(line, delimiter);
        if (tokens.size() <= label_it->second) {
            // malformed row; skip
            continue;
        }

        LabeledSequence sample;
        sample.id = "iot_line_" + std::to_string(line_number);
        if (id_orig_h_col < tokens.size()) {
            sample.host = tokens[id_orig_h_col];
        }
        if (id_resp_h_col < tokens.size()) {
            sample.resp_host = tokens[id_resp_h_col];
        }
        if (uid_col < tokens.size()) {
            sample.uid = tokens[uid_col];
        }
        if (ts_col < tokens.size()) {
            try {
                sample.ts = std::stod(tokens[ts_col]);
            } catch (...) {
                sample.ts = 0.0;
            }
        }
        sample.label = is_true_label(tokens[label_it->second]);

        // Helper to map a dataset column into a prefixed symbol token used by
        // the PTA/DFA pipeline. We prefix the raw column value (e.g. 'tcp')
        // with a short namespace like 'proto=' so that different features don't
        // collide in the alphabet.
        auto add_symbol = [&](std::size_t column, const std::string& prefix) {
            if (column < tokens.size()) {
                const auto& value = tokens[column];
                if (!value.empty() && value != "-") {
                    sample.symbols.push_back(prefix + value);
                }
            }
        };

        add_symbol(proto_col, "proto=");
        add_symbol(conn_state_col, "state=");
        add_symbol(service_col, "service=");

        if (detailed_label_col < tokens.size()) {
            // Ensure we do not leak the second label column as part of the alphabet.
            // The value was already consumed for supervised labels above.
        }

        if (sample.symbols.empty()) {
            // If the row had no usable feature columns, insert a sentinel token
            // so the sequence is not empty; this prevents dropping the sample in
            // later stages and makes it explicit that the sample had no
            // extractable features.
            sample.symbols.push_back("symbol=unknown");
        }

        samples.push_back(std::move(sample));
    }

    return samples;
}

DatasetSplit train_test_split(const std::vector<LabeledSequence>& data,
                              double train_ratio,
                              unsigned int seed) {
    if (train_ratio <= 0.0 || train_ratio >= 1.0) {
        throw std::invalid_argument("train_ratio must be in (0, 1).");
    }
    if (data.empty()) {
        return {};
    }

    std::vector<LabeledSequence> shuffled = data;
    std::mt19937 gen(seed);
    std::shuffle(shuffled.begin(), shuffled.end(), gen);

    std::size_t train_count = static_cast<std::size_t>(shuffled.size() * train_ratio);
    if (train_count == 0) {
        train_count = 1;
    } else if (train_count == shuffled.size()) {
        train_count = shuffled.size() - 1;
    }

    DatasetSplit split;
    split.train.insert(split.train.end(), shuffled.begin(), shuffled.begin() + train_count);
    split.test.insert(split.test.end(), shuffled.begin() + train_count, shuffled.end());
    return split;
}

}  // namespace automata_security
