#include "prx/libSceUlt/include/Api.hpp"
#include "prx/libkernel/include/Api.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <semaphore>
#include <stdexcept>
#include <thread>

namespace {

void Require(bool value, int line) {
    if (value) return;
    std::fprintf(stderr, "ULT lifecycle check failed at line %d\n", line);
    std::abort();
}

#define CHECK(value) Require((value), __LINE__)

struct alignas(8) Runtime { std::byte bytes[4096]{}; };
struct alignas(8) Thread { std::byte bytes[512]{}; };

struct HostThread {
    std::thread thread;
    void* result = nullptr;
};

std::atomic<bool> entryFinished{false};
std::atomic<int> joinCalls{0};
std::atomic<int> hostThreads{0};
std::binary_semaphore joining{0};
std::binary_semaphore releaseJoin{0};
bool gateJoin = false;
int createFailure = 0;
int joinFailure = 0;

void Await(std::binary_semaphore& gate) {
    CHECK(gate.try_acquire_for(std::chrono::seconds(2)));
}

std::int32_t APS5_VABI Entry(std::uint64_t argument) {
    void* self = nullptr;
    CHECK(sceUltUlthreadGetSelf(&self) == ULT_OK && self != nullptr);
    CHECK(sceUltUlthreadYield() == ULT_OK);
    return static_cast<std::int32_t>(argument);
}

void Create(Runtime& runtime, Thread& thread) {
    CHECK(sceUltUlthreadRuntimeCreate(&runtime, "runtime", 1, 1, nullptr, nullptr, 0) == ULT_OK);
    CHECK(sceUltUlthreadCreate(&thread, "thread", Entry, 73, nullptr, 0, &runtime, nullptr, 0) == ULT_OK);
    entryFinished.wait(false);
}

void Finish(Runtime& runtime, Thread& thread) {
    std::int32_t status = -1;
    CHECK(sceUltUlthreadJoin(&thread, &status) == ULT_OK && status == 73);
    CHECK(hostThreads.load() == 0);
    CHECK(sceUltUlthreadJoin(&thread, &status) == ULT_ERROR_STATE && status == 73);
    CHECK(sceUltUlthreadRuntimeDestroy(&runtime) == ULT_OK);
    CHECK(sceUltFinalize() == ULT_OK);
}

void CreateFailure(int failure) {
    Runtime runtime;
    Thread thread;
    CHECK(sceUltUlthreadRuntimeCreate(&runtime, "runtime", 1, 1, nullptr, nullptr, 0) == ULT_OK);
    createFailure = failure;
    bool threw = false;
    int result = ULT_OK;
    try {
        result = sceUltUlthreadCreate(&thread, "thread", Entry, 73, nullptr, 0, &runtime, nullptr, 0);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw == (failure != 1));
    if (failure == 1) CHECK(result == ULT_ERROR_AGAIN);
    if (failure == 3) {
        CHECK(sceUltFinalize() == ULT_ERROR_BUSY);
        CHECK(sceUltUlthreadRuntimeDestroy(&runtime) == ULT_ERROR_STATE);
        Finish(runtime, thread);
        return;
    }
    CHECK(hostThreads.load() == 0 && !entryFinished.load());
    CHECK(sceUltUlthreadTryJoin(&thread, nullptr) == ULT_ERROR_STATE);
    CHECK(sceUltUlthreadCreate(&thread, "retry", Entry, 73, nullptr, 0, &runtime, nullptr, 0) == ULT_OK);
    Finish(runtime, thread);
}

void Ownership(bool nonblocking) {
    Runtime runtime;
    Thread thread;
    Create(runtime, thread);
    gateJoin = true;
    std::int32_t firstStatus = -1;
    int firstResult = ULT_ERROR_STATE;
    std::thread first([&] {
        firstResult = nonblocking ? sceUltUlthreadTryJoin(&thread, &firstStatus) : sceUltUlthreadJoin(&thread, &firstStatus);
    });
    Await(joining);
    std::int32_t secondStatus = -2;
    CHECK(sceUltUlthreadJoin(&thread, &secondStatus) == ULT_ERROR_STATE && secondStatus == -2);
    CHECK(sceUltUlthreadTryJoin(&thread, &secondStatus) == ULT_ERROR_STATE && secondStatus == -2);
    CHECK(joinCalls.load() == 1);
    CHECK(sceUltUlthreadCreate(&thread, "replacement", Entry, 74, nullptr, 0, &runtime, nullptr, 0) == ULT_ERROR_STATE);
    CHECK(sceUltUlthreadRuntimeDestroy(&runtime) == ULT_ERROR_STATE);
    CHECK(sceUltFinalize() == ULT_ERROR_BUSY);
    releaseJoin.release();
    first.join();
    CHECK(firstResult == ULT_OK && firstStatus == 73 && hostThreads.load() == 0);
    CHECK(sceUltUlthreadTryJoin(&thread, &secondStatus) == ULT_ERROR_STATE && secondStatus == -2);
    gateJoin = false;
    entryFinished.store(false);
    CHECK(sceUltUlthreadCreate(&thread, "replacement", Entry, 73, nullptr, 0, &runtime, nullptr, 0) == ULT_OK);
    Finish(runtime, thread);
}

void JoinFailure(int failure) {
    Runtime runtime;
    Thread thread;
    Create(runtime, thread);
    joinFailure = failure;
    std::int32_t status = -1;
    bool threw = false;
    int result = ULT_OK;
    try {
        result = sceUltUlthreadJoin(&thread, &status);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw == (failure == 2));
    if (!threw) CHECK(result == ULT_ERROR_STATE);
    CHECK(status == -1 && hostThreads.load() == 1);
    Finish(runtime, thread);
}

}

extern "C" {

int APS5_VABI scePthreadCreate(Pthread* value, const PthreadAttr*, PthreadEntry entry, void* argument, const char*) {
    const int failure = createFailure;
    createFailure = 0;
    if (failure == 1) return 11;
    if (failure == 2) throw std::runtime_error("Injected prepublication creation failure");
    auto state = std::make_unique<HostThread>();
    auto* raw = state.get();
    state->thread = std::thread([=] {
        raw->result = entry(argument);
        entryFinished.store(true);
        entryFinished.notify_all();
    });
    ++hostThreads;
    *value = reinterpret_cast<Pthread>(state.release());
    if (failure == 3) throw std::runtime_error("Injected postpublication creation failure");
    return 0;
}

int APS5_VABI scePthreadJoin(Pthread value, void** result) {
    const int call = joinCalls.fetch_add(1);
    if (gateJoin) {
        if (call != 0) return 22;
        joining.release();
        Await(releaseJoin);
    }
    const int failure = joinFailure;
    joinFailure = 0;
    if (failure == 1) return 22;
    if (failure == 2) throw std::runtime_error("Injected precommit join failure");
    CHECK(value != nullptr);
    std::unique_ptr<HostThread> state(reinterpret_cast<HostThread*>(value));
    state->thread.join();
    if (result != nullptr) *result = state->result;
    --hostThreads;
    return 0;
}

}

int main(int argc, char** argv) {
    CHECK(argc == 2);
    if (std::strcmp(argv[1], "create-error") == 0) CreateFailure(1);
    else if (std::strcmp(argv[1], "create-exception") == 0) CreateFailure(2);
    else if (std::strcmp(argv[1], "published-exception") == 0) CreateFailure(3);
    else if (std::strcmp(argv[1], "join-owner") == 0) Ownership(false);
    else if (std::strcmp(argv[1], "tryjoin-owner") == 0) Ownership(true);
    else if (std::strcmp(argv[1], "join-error") == 0) JoinFailure(1);
    else if (std::strcmp(argv[1], "join-exception") == 0) JoinFailure(2);
    else CHECK(false);
}
