#include "LogParser.hpp"
#include "LogAnalyzer.hpp"
#include "ThreadPool.hpp"
#include "SuspiciousActivityDetector.hpp"
#include "ReportGenerator.hpp"
#include <gtest/gtest.h>
#include <fstream>
#include <atomic>
using namespace multilog;
TEST(Parser, ParsesApacheAndAppAndRejectsMalformed){LogParser p;auto a=p.parse("192.0.2.10 - - [10/Oct/2024:13:55:36 +0000] \"GET /index.html HTTP/1.1\" 200 123");ASSERT_TRUE(a);EXPECT_EQ(a->status,200);EXPECT_EQ(a->ip,"192.0.2.10");auto b=p.parse("2024-10-10 13:55:36 ERROR [198.51.100.2] database unavailable");ASSERT_TRUE(b);EXPECT_EQ(b->severity,"ERROR");EXPECT_FALSE(p.parse("bad line"));}
TEST(ThreadPool, ExecutesAllTasks){std::atomic<int> n{0};{ThreadPool p(4,4);for(int i=0;i<100;++i)p.submit([&]{++n;});p.wait();EXPECT_EQ(p.completedTasks(),100u);}EXPECT_EQ(n,100);}
TEST(ThreadPool, PropagatesTaskExceptions){ThreadPool p(2,2);p.submit([]{throw std::runtime_error("task failure");});EXPECT_THROW(p.wait(),std::runtime_error);}
TEST(Analyzer, SequentialAndParallelAgree){auto path=std::filesystem::temp_directory_path()/"multilog_test.log";{std::ofstream f(path);f<<"192.0.2.1 - - [10/Oct/2024:13:55:36 +0000] \"GET /a HTTP/1.1\" 200 10\n";f<<"192.0.2.1 - - [10/Oct/2024:13:56:36 +0000] \"GET /b HTTP/1.1\" 404 10\n";f<<"not a log\n";}LogAnalyzer a;auto one=a.analyze(path,1),many=a.analyze(path,3);EXPECT_EQ(one.total,3);EXPECT_EQ(one.invalid,1);EXPECT_EQ(one.filtered,many.filtered);EXPECT_EQ(one.statusClasses,many.statusClasses);EXPECT_EQ(one.ips,many.ips);}
TEST(Detector, FindsRepeatedFailures){AnalysisResult r;LogEntry e;e.ip="192.0.2.3";e.status=401;e.format=LogFormat::Apache;e.hasTimestamp=true;e.timestamp=std::chrono::system_clock::from_time_t(1728568536);r.entries.assign(5,e);EXPECT_FALSE(SuspiciousActivityDetector{}.detect(r).empty());}
TEST(Reports, EmitsJsonAndCsv){AnalysisResult r;r.total=1;r.valid=1;EXPECT_NE(ReportGenerator::json(r,{}).find("\"total\": 1"),std::string::npos);EXPECT_NE(ReportGenerator::csv(r,{}).find("record_type"),std::string::npos);}
TEST(Analyzer, MissingFileFails){EXPECT_THROW(LogAnalyzer{}.analyze("this-file-should-not-exist.log"),std::runtime_error);}
