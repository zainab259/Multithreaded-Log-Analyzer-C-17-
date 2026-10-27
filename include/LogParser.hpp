#pragma once
#include "LogEntry.hpp"
#include <optional>
namespace multilog {
class LogParser {
public:
    std::optional<LogEntry> parse(const std::string& line) const;
private:
    std::optional<LogEntry> parseApache(const std::string& line) const;
    std::optional<LogEntry> parseApplication(const std::string& line) const;
};
}
