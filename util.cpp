#include <chrono>
#include <mutex>
#include <queue>
#include <thread>
#include <cstdio>

extern "C" {
    void pool(long amount);

    std::mutex mutex;
    std::queue<void*> queue;

    uint64_t getTimestamp() {
        return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()).time_since_epoch().count();
    }

    void thread(long amount) {
        new std::thread(pool, amount);
    }

    void push(void *easy) {
        mutex.lock();
        queue.push(easy);
        mutex.unlock();
    }

    void *pop() {
        if (!queue.size()) {
            return 0;
        }
        void *easy = queue.front();
        mutex.lock();
        queue.pop();
        mutex.unlock();
        return easy;
    }
}
