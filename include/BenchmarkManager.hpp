#pragma once
#include "LogAnalyzer.hpp"
namespace multilog { struct BenchmarkRow{std::size_t threads=1;double seconds=0,linesPerSecond=0,speedup=0;}; class BenchmarkManager{public:std::vector<BenchmarkRow> run(const std::filesystem::path&,std::size_t repetitions=1) const;}; }
