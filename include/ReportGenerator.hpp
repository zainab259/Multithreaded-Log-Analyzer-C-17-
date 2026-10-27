#pragma once
#include "LogAnalyzer.hpp"
#include <string>
namespace multilog {
class ReportGenerator { public: static std::string terminal(const AnalysisResult&,const std::vector<Alert>&); static std::string json(const AnalysisResult&,const std::vector<Alert>&); static std::string csv(const AnalysisResult&,const std::vector<Alert>&); static void write(const std::filesystem::path&,const std::string&); };
}
