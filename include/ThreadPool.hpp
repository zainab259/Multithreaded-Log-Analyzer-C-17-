#pragma once
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <vector>
#include <atomic>
#include <exception>

namespace multilog {
class ThreadPool {
public:
    explicit ThreadPool(std::size_t workers, std::size_t capacity=64);
    ~ThreadPool();
    ThreadPool(const ThreadPool&)=delete; ThreadPool& operator=(const ThreadPool&)=delete;
    void submit(std::function<void()> task);
    void wait();
    std::size_t completedTasks() const noexcept { return completed_.load(); }
private:
    void worker();
    std::vector<std::thread> workers_; std::queue<std::function<void()>> tasks_;
    std::mutex mutex_; std::condition_variable ready_, space_, done_;
    std::size_t capacity_, active_=0; bool stopping_=false;
    std::atomic<std::size_t> completed_{0};
    std::exception_ptr firstException_;
};
}
