#pragma once

#include <string>

namespace automata_security {

inline constexpr const char* kDefaultIotDataset =
    "datasets/iotMalware/CTU-IoT-Malware-Capture-1-1conn.log.labeled.csv";

inline constexpr double kDefaultTrainRatio = 0.7;

inline const std::string kVersion = "0.2.0";

}  // namespace automata_security
