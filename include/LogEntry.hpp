#pragma once
#include <optional>
#include <string>
#include <chrono>

namespace multilog {
enum class LogFormat { Apache, Application };
struct LogEntry {
    std::string raw, ip, method, url, severity, message;
    int status = 0;
    std::chrono::system_clock::time_point timestamp{};
    bool hasTimestamp = false;
    LogFormat format = LogFormat::Application;
};
struct Alert { std::string type, sourceIp, window, reason, severity; std::size_t count = 0; };
}
