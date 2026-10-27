#include "LogParser.hpp"
#include <regex>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace multilog {
namespace {
std::optional<std::chrono::system_clock::time_point> parseTime(const std::string& s, const char* fmt) {
    std::tm tm{}; std::istringstream in(s); in >> std::get_time(&tm, fmt);
    if (in.fail()) return std::nullopt;
#ifdef _WIN32
    auto value = _mkgmtime(&tm);
#else
    auto value = timegm(&tm);
#endif
    if (value == static_cast<std::time_t>(-1)) return std::nullopt;
    return std::chrono::system_clock::from_time_t(value);
}
}
std::optional<LogEntry> LogParser::parse(const std::string& line) const {
    if (line.empty()) return std::nullopt;
    if (auto e = parseApache(line)) return e;
    return parseApplication(line);
}
std::optional<LogEntry> LogParser::parseApache(const std::string& line) const {
    static const std::regex pattern(R"(^([^ ]+) [^ ]+ [^ ]+ \[([^]]+)\] \"([A-Z]+) ([^ ]+) [^\"]+\" (\d{3}) (?:\d+|-)\s*(.*)$)");
    std::smatch m; if (!std::regex_match(line, m, pattern)) return std::nullopt;
    LogEntry e; e.raw=line; e.ip=m[1]; e.method=m[3]; e.url=m[4]; e.status=std::stoi(m[5]); e.format=LogFormat::Apache;
    const auto ts = parseTime(m[2], "%d/%b/%Y:%H:%M:%S"); if (!ts) return std::nullopt; e.timestamp=*ts; e.hasTimestamp=true;
    e.severity=e.status>=500?"ERROR":e.status>=400?"WARNING":"INFO"; e.message=m[6]; return e;
}
std::optional<LogEntry> LogParser::parseApplication(const std::string& line) const {
    // Documented format: YYYY-MM-DD HH:MM:SS LEVEL [IP] message
    static const std::regex pattern(R"(^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (INFO|WARNING|WARN|ERROR|CRITICAL) \[([^]]+)\] (.+)$)");
    std::smatch m; if (!std::regex_match(line,m,pattern)) return std::nullopt;
    auto ts=parseTime(m[1],"%Y-%m-%d %H:%M:%S"); if (!ts) return std::nullopt;
    LogEntry e; e.raw=line; e.timestamp=*ts; e.hasTimestamp=true; e.severity=m[2]; if(e.severity=="WARN") e.severity="WARNING"; e.ip=m[3]; e.message=m[4]; return e;
}
}
