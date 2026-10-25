#include "prx/libkernel/include/Api.hpp"
#include "prx/libkernel/Pthread/include/Pthread.hpp"
#include "prx/libkernel/KernelErrors.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <thread>

static constexpr int SCE_OK = 0;

static void Require(bool condition) { if (!condition) std::abort(); }

struct Worker {
    std::atomic<bool> started{false};
    std::atomic<bool> release{false};
};

static void* APS5_VABI Wait(void* opaque) {
    auto* worker = static_cast<Worker*>(opaque);
    worker->started.store(true);
    while (!worker->release.load()) std::this_thread::yield();
    return nullptr;
}

static void WaitUntilReleased(Pthread thread) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    int priority = 0;
    while (scePthreadGetprio(thread, &priority) != SCE_KERNEL_ERROR_ESRCH) {
        Require(std::chrono::steady_clock::now() < deadline);
        std::this_thread::yield();
    }
}

int main() {
    for (int round = 0; round < 20; ++round) {
        Worker worker;
        Pthread thread = nullptr;
        Require(scePthreadCreate(&thread, nullptr, Wait, &worker, "released") == SCE_OK);
        while (!worker.started.load()) std::this_thread::yield();
        Require(scePthreadDetach(thread) == SCE_OK);
        worker.release.store(true);
        WaitUntilReleased(thread);
        Require(scePthreadJoin(thread, nullptr) == SCE_KERNEL_ERROR_ESRCH);
        Require(scePthreadDetach(thread) == SCE_KERNEL_ERROR_ESRCH);
        Require(scePthreadCancel(thread) == SCE_KERNEL_ERROR_ESRCH);
    }
    return 0;
}
