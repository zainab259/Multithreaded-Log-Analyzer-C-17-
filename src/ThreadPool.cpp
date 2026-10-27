#include "ThreadPool.hpp"
#include <stdexcept>
namespace multilog {
ThreadPool::ThreadPool(std::size_t n,std::size_t capacity):capacity_(capacity){
    if(!n||!capacity) throw std::invalid_argument("thread count and queue capacity must be positive");
    try { for(std::size_t i=0;i<n;++i) workers_.emplace_back(&ThreadPool::worker,this); }
    catch(...) { {std::lock_guard<std::mutex> lock(mutex_);stopping_=true;} ready_.notify_all(); for(auto& t:workers_) if(t.joinable())t.join(); throw; }
}
ThreadPool::~ThreadPool(){ {std::lock_guard<std::mutex> lock(mutex_);stopping_=true;} ready_.notify_all(); space_.notify_all(); for(auto& t:workers_) if(t.joinable())t.join(); }
void ThreadPool::submit(std::function<void()> task){ std::unique_lock<std::mutex> lock(mutex_); space_.wait(lock,[this]{return tasks_.size()<capacity_||stopping_;}); if(stopping_)throw std::runtime_error("thread pool is stopping"); tasks_.push(std::move(task)); ready_.notify_one(); }
void ThreadPool::wait(){std::unique_lock<std::mutex> lock(mutex_);done_.wait(lock,[this]{return tasks_.empty()&&active_==0;});auto error=firstException_;firstException_=nullptr;lock.unlock();if(error)std::rethrow_exception(error);}
void ThreadPool::worker(){ for(;;){std::function<void()> task; {std::unique_lock<std::mutex> lock(mutex_); ready_.wait(lock,[this]{return stopping_||!tasks_.empty();}); if(stopping_&&tasks_.empty())return; task=std::move(tasks_.front());tasks_.pop();++active_;space_.notify_one();} try{task();}catch(...){std::lock_guard<std::mutex> lock(mutex_);if(!firstException_)firstException_=std::current_exception();} completed_.fetch_add(1,std::memory_order_relaxed); {std::lock_guard<std::mutex> lock(mutex_);--active_;if(tasks_.empty()&&active_==0)done_.notify_all();} } }
}
