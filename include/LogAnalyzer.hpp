#pragma once
#include "LogEntry.hpp"
#include <unordered_map>
#include <map>
#include <vector>
#include <filesystem>
#include <optional>
#include <chrono>
#include <cstdint>
namespace multilog {
struct Filter { std::string level, ip, keyword; int status=0; std::optional<std::chrono::system_clock::time_point> start,end; bool matches(const LogEntry&) const; };
struct AnalysisResult {
    std::size_t total=0, valid=0, invalid=0, filtered=0; std::map<std::string,std::size_t> severities;
    std::map<int,std::size_t> statusClasses; std::unordered_map<std::string,std::size_t> ips, urls, errors;
    std::map<std::int64_t,std::size_t> requestsPerMinute; std::optional<std::chrono::system_clock::time_point> earliest,latest;
    std::vector<LogEntry> entries; double seconds=0.0; std::size_t threadCount=1;
};
class LogAnalyzer {
public:
 AnalysisResult analyze(const std::filesystem::path&,std::size_t threads=1,const Filter& filter={},std::size_t batchSize=512) const;
};
}
