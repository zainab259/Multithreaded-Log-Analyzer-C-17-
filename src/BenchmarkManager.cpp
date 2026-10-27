#include "BenchmarkManager.hpp"
#include <algorithm>
#include <stdexcept>
namespace multilog { std::vector<BenchmarkRow> BenchmarkManager::run(const std::filesystem::path&p,std::size_t reps)const{if(!reps)throw std::invalid_argument("repetitions must be positive");LogAnalyzer a;std::vector<BenchmarkRow> rows;for(auto n:{1u,2u,4u,8u}){double total=0;std::size_t lines=0;for(std::size_t i=0;i<reps;++i){auto r=a.analyze(p,n);total+=r.seconds;lines=r.total;}double avg=total/reps;rows.push_back({n,avg,avg>0?lines/avg:0,0});}auto base=rows.front().seconds;for(auto&r:rows)r.speedup=r.seconds>0?base/r.seconds:0;return rows;} }
