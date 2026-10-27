#include "LogAnalyzer.hpp"
#include "LogParser.hpp"
#include "ThreadPool.hpp"
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <algorithm>
#include <memory>
#include <iterator>
namespace multilog {
bool Filter::matches(const LogEntry& e) const { if(!level.empty()&&e.severity!=level)return false;if(!ip.empty()&&e.ip!=ip)return false;if(status&&e.status!=status)return false;if(!keyword.empty()&&e.raw.find(keyword)==std::string::npos)return false;if(start&&(!e.hasTimestamp||e.timestamp<*start))return false;if(end&&(!e.hasTimestamp||e.timestamp>*end))return false;return true; }
AnalysisResult LogAnalyzer::analyze(const std::filesystem::path& path,std::size_t threads,const Filter& filter,std::size_t batchSize) const {
 if(!threads||!batchSize)throw std::invalid_argument("threads and batch size must be positive"); std::ifstream input(path);if(!input)throw std::runtime_error("cannot open input file: "+path.string());
 auto begin=std::chrono::steady_clock::now(); AnalysisResult result;result.threadCount=threads;LogParser parser;std::mutex aggregate;
 auto consume=[&](std::vector<std::string> lines){std::size_t total=lines.size(),valid=0,invalid=0;std::map<std::string,std::size_t> sev,err;std::map<int,std::size_t> cls;std::unordered_map<std::string,std::size_t> ips,urls;std::map<std::int64_t,std::size_t> rpm;std::vector<LogEntry> entries;std::optional<std::chrono::system_clock::time_point> lo,hi;
  for(const auto& line:lines){auto parsed=parser.parse(line);if(!parsed){++invalid;continue;}++valid;auto&e=*parsed;if(!filter.matches(e))continue;entries.push_back(e);++sev[e.severity];if(e.status){++cls[e.status/100];++urls[e.url];}if(!e.ip.empty())++ips[e.ip];if(e.severity=="ERROR"||e.severity=="CRITICAL")++err[e.message];if(e.hasTimestamp){auto t=std::chrono::duration_cast<std::chrono::seconds>(e.timestamp.time_since_epoch()).count();++rpm[t/60];if(!lo||e.timestamp<*lo)lo=e.timestamp;if(!hi||e.timestamp>*hi)hi=e.timestamp;}}
  std::lock_guard<std::mutex> lock(aggregate);result.total+=total;result.valid+=valid;result.invalid+=invalid;result.filtered+=entries.size();for(auto&p:sev)result.severities[p.first]+=p.second;for(auto&p:cls)result.statusClasses[p.first]+=p.second;for(auto&p:ips)result.ips[p.first]+=p.second;for(auto&p:urls)result.urls[p.first]+=p.second;for(auto&p:err)result.errors[p.first]+=p.second;for(auto&p:rpm)result.requestsPerMinute[p.first]+=p.second;if(lo&&(!result.earliest||*lo<*result.earliest))result.earliest=lo;if(hi&&(!result.latest||*hi>*result.latest))result.latest=hi;result.entries.insert(result.entries.end(),std::make_move_iterator(entries.begin()),std::make_move_iterator(entries.end()));};
 std::unique_ptr<ThreadPool> pool;if(threads>1)pool=std::make_unique<ThreadPool>(threads,std::max<std::size_t>(2,threads*2));std::string line;std::vector<std::string> batch;batch.reserve(batchSize);
 while(std::getline(input,line)){batch.push_back(std::move(line));if(batch.size()>=batchSize){auto work=std::move(batch);if(pool)pool->submit([&,w=std::move(work)]()mutable{consume(std::move(w));});else consume(std::move(work));batch.clear();batch.reserve(batchSize);}}
 if(input.bad())throw std::runtime_error("error reading input file: "+path.string());if(!batch.empty()){auto work=std::move(batch);if(pool)pool->submit([&,w=std::move(work)]()mutable{consume(std::move(w));});else consume(std::move(work));}if(pool)pool->wait();result.seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count();return result;
}
}
