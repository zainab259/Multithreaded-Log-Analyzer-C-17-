#pragma once
#include "LogAnalyzer.hpp"
namespace multilog {
struct DetectionConfig { std::size_t authThreshold=5, notFoundThreshold=10, serverErrorThreshold=5, highVolumeThreshold=120, unsuccessfulThreshold=8, windowMinutes=5; };
class SuspiciousActivityDetector { public: std::vector<Alert> detect(const AnalysisResult&,const DetectionConfig& config={}) const; };
}
