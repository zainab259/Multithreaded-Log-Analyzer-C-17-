#include "LogAnalyzer.hpp"
#include "ReportGenerator.hpp"
#include "SuspiciousActivityDetector.hpp"
#include "BenchmarkManager.hpp"
#include <iostream>
#include <thread>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <limits>
using namespace multilog;
namespace {
void help(){std::cout<<"MultiLog Analyzer - multithreaded log analysis\nUsage: multilog --file PATH [--threads N] [--level LEVEL] [--ip ADDRESS] [--status CODE] [--from YYYY-MM-DDTHH:MM:SS] [--to YYYY-MM-DDTHH:MM:SS] [--keyword TEXT] [--output terminal|json|csv] [--detect-suspicious] [--window-minutes N]\n       multilog --benchmark --file PATH [--repetitions N]\nFormats: Apache/Nginx combined access logs; application format YYYY-MM-DD HH:MM:SS LEVEL [IP] message. Times without offsets are UTC.\n";}
std::size_t number(const std::string&s,const std::string&name){if(s.empty()||s.find_first_not_of("0123456789")!=std::string::npos)throw std::invalid_argument(name+" must be a positive integer");std::size_t used=0;auto n=std::stoull(s,&used);if(used!=s.size()||n==0||n>std::numeric_limits<std::size_t>::max())throw std::invalid_argument(name+" must be a positive integer in range");return static_cast<std::size_t>(n);}
std::chrono::system_clock::time_point parseCliTime(const std::string&s){std::tm tm{};std::istringstream in(s);in>>std::get_time(&tm,"%Y-%m-%dT%H:%M:%S");if(in.fail()||in.peek()!=std::char_traits<char>::eof())throw std::invalid_argument("timestamp must use YYYY-MM-DDTHH:MM:SS");
#ifdef _WIN32
auto t=_mkgmtime(&tm);
#else
auto t=timegm(&tm);
#endif
if(t==static_cast<std::time_t>(-1))throw std::invalid_argument("invalid timestamp");return std::chrono::system_clock::from_time_t(t);}
}
int main(int argc,char**argv){try{std::filesystem::path file;std::size_t threads=std::max(1u,std::thread::hardware_concurrency()),reps=1;std::string output="terminal";bool detect=false,benchmark=false;Filter filter;DetectionConfig detection;
for(int i=1;i<argc;++i){std::string arg=argv[i];auto value=[&](){if(i+1>=argc)throw std::invalid_argument("missing value for "+arg);return std::string(argv[++i]);};if(arg=="--help"||arg=="-h"){help();return 0;}else if(arg=="--file")file=value();else if(arg=="--threads")threads=number(value(),"threads");else if(arg=="--output")output=value();else if(arg=="--level"){filter.level=value();if(filter.level=="WARN")filter.level="WARNING";}else if(arg=="--ip")filter.ip=value();else if(arg=="--status")filter.status=std::stoi(value());else if(arg=="--from")filter.start=parseCliTime(value());else if(arg=="--to")filter.end=parseCliTime(value());else if(arg=="--keyword")filter.keyword=value();else if(arg=="--window-minutes")detection.windowMinutes=number(value(),"window-minutes");else if(arg=="--detect-suspicious")detect=true;else if(arg=="--benchmark")benchmark=true;else if(arg=="--repetitions")reps=number(value(),"repetitions");else throw std::invalid_argument("unknown argument: "+arg);}
if(file.empty())throw std::invalid_argument("--file is required");if(file.extension()!=".log"&&file.extension()!=".txt")throw std::invalid_argument("input extension must be .log or .txt");if(benchmark){BenchmarkManager b;auto rows=b.run(file,reps);std::cout<<"threads,seconds,lines_per_second,speedup\n";for(auto&r:rows)std::cout<<r.threads<<','<<r.seconds<<','<<r.linesPerSecond<<','<<r.speedup<<'\n';return 0;}
LogAnalyzer analyzer;auto result=analyzer.analyze(file,threads,filter);std::vector<Alert>alerts;if(detect)alerts=SuspiciousActivityDetector{}.detect(result,detection);if(output=="terminal")std::cout<<ReportGenerator::terminal(result,alerts);else if(output=="json"||output=="csv"){auto content=output=="json"?ReportGenerator::json(result,alerts):ReportGenerator::csv(result,alerts);auto path=std::filesystem::path("reports")/(file.stem().string()+"_report."+output);ReportGenerator::write(path,content);std::cout<<"Report written to "<<path.string()<<"\n";}else throw std::invalid_argument("--output must be terminal, json, or csv");return 0;
}catch(const std::exception&e){std::cerr<<"error: "<<e.what()<<"\nUse --help for usage.\n";return 2;}}
