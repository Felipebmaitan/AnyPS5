#include "prx/libkernel/include/Api.hpp"
#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include "prx/libkernel/Pthread/include/Pthread.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libSceNet/include/Net.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

static void Require(bool value, const char* message) {
    if (value) return;
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
}

template <class TPredicate>
static bool Observe(TPredicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::yield();
    }
    return true;
}

struct State {
    std::vector<GuestPollDescriptor> descriptors;
    int output = -1;
    int timeout = -1;
    PthreadKey key = -1;
    bool disabled = false;
    bool pending = false;
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> waiting{false};
    std::atomic<bool> returned{false};
    std::atomic<int> cleanups{0};
    std::atomic<int> destructors{0};
    int result = -2;
    int error = 0;
    bool jumpOnSignal = false;
    alignas(16) std::array<std::uint64_t, 12> jump{};
    std::atomic<int> signals{0};
};
static State* observed = nullptr;
static void APS5_VABI SignalHandler(int, void*) {
    observed->signals.fetch_add(1);
    if (observed->jumpOnSignal) longjmp_nid_postfix(observed->jump.data(), 1);
}
static void Hook(int stage) {
    if (stage == 1) observed->waiting.store(true);
}
static void APS5_VABI Cleanup(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    Require(state.cleanups.fetch_add(1) == 0, "cleanup repeated");
    Require(state.destructors.load() == 0, "TSD before cleanup");
}
static void APS5_VABI Destroy(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    Require(state.cleanups.load() == 1, "missing cleanup");
    Require(state.destructors.fetch_add(1) == 0, "TSD repeated");
}
static void* APS5_VABI Poller(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    if (state.disabled) Require(scePthreadSetcancelstate(GUEST_CANCEL_DISABLE, nullptr) == 0, "disable cancellation");
    Require(scePthreadSetspecific(state.key, &state) == 0, "set TSD");
    CleanupHandler cleanup{};
    __pthread_cleanup_push_imp_nid_postfix(Cleanup, &state, &cleanup);
    state.entered.store(true);
    if (state.pending) Require(Observe([&] { return state.release.load(); }), "release pending poll");
    if (state.jumpOnSignal && setjmp_nid_postfix(state.jump.data()) != 0) state.result = -3;
    else state.result = poll_nid_postfix(state.descriptors.data(), static_cast<std::uint32_t>(state.descriptors.size()), state.timeout);
    state.error = *__error_nid_postfix();
    state.returned.store(true);
    if (state.disabled) {
        Require(state.result == (state.descriptors.empty() ? 0 : 1), "disabled poll lost completion");
        Require(scePthreadSetcancelstate(GUEST_CANCEL_ENABLE, nullptr) == 0, "enable cancellation");
        scePthreadTestcancel();
    }
    __pthread_cleanup_pop_imp_nid_postfix(1);
    return reinterpret_cast<void*>(std::uintptr_t{7});
}

static void Pair(State& state, bool net) {
    const int listener = socket_nid_postfix(2, 1, 0);
    Require(listener >= 0, "listener");
    std::array<unsigned char, 16> address{16, 2, 0, 0, 127, 0, 0, 1};
    Require(bind_nid_postfix(listener, address.data(), address.size()) == 0, "bind");
    std::uint32_t length = address.size();
    Require(getsockname_nid_postfix(listener, address.data(), &length) == 0, "getsockname");
    Require(listen_nid_postfix(listener, 4) == 0, "listen");
    const int input = net ? sceNetSocket("poll", 2, 1, 0) : socket_nid_postfix(2, 1, 0);
    Require(input >= 0, "client");
    Require((net ? sceNetConnect(input, address.data(), address.size()) : connect_nid_postfix(input, address.data(), address.size())) == 0, "connect");
    state.output = accept_nid_postfix(listener, nullptr, nullptr);
    Require(state.output >= 0, "accept");
    Require(close_nid_postfix(listener) == 0, "close listener");
    state.descriptors.push_back({input, 1, -1});
}

static void Run(const std::string& transport, const std::string& scenario) {
    State state;
    const bool empty = transport == "empty";
    const bool net = transport == "net";
    const bool queue = transport == "kqueue";
    if (transport == "pipe" || transport == "hostpipe") {
        int pipe[2];
        if (transport == "pipe") Require(pipe_nid_postfix(pipe) == 0, "pipe");
        else {
#ifdef _WIN32
            Require(::_pipe(pipe, 4096, _O_BINARY) == 0, "native pipe");
#else
            Require(::pipe(pipe) == 0, "native pipe");
#endif
        }
        state.descriptors.push_back({pipe[0], 1, -1});
        state.output = pipe[1];
    } else if (queue) {
        const int descriptor = kqueue_nid_postfix();
        Require(descriptor >= 0, "kqueue");
        KernelEvent change{};
        change.ident = 1;
        change.filter = -11;
        change.flags = 1;
        Require(kevent_nid_postfix(descriptor, &change, 1, nullptr, 0, nullptr) == 0, "add queue event");
        state.descriptors.push_back({descriptor, 1, -1});
    } else if (!empty) Pair(state, net);
    const auto complete = [&] {
        if (queue) {
            KernelEvent change{};
            change.ident = 1;
            change.filter = -11;
            change.fflags = 0x01000000;
            Require(kevent_nid_postfix(state.descriptors.front().descriptor, &change, 1, nullptr, 0, nullptr) == 0, "trigger queue event");
        } else Require(write_nid_postfix(state.output, "x", 1) == 1, "complete readiness");
    };
    state.disabled = scenario == "disabled";
    state.pending = scenario == "pending";
    const bool signal = scenario == "signal" || scenario == "signal_jump";
    state.jumpOnSignal = scenario == "signal_jump";
    if (scenario == "timeout" || (empty && state.disabled)) state.timeout = 100;
    if (scenario == "zero" || scenario == "invalid") state.timeout = 0;
    if (scenario == "invalid") state.descriptors.push_back({100000, 1, -1});
    if (scenario == "duplicate") state.descriptors.push_back(state.descriptors.front());
    if (scenario == "nonblocking") Require(fcntl_nid_postfix(state.descriptors.front().descriptor, 4, 4) == 0, "nonblocking");
    int extra[2]{-1, -1};
    int replacement[2]{-1, -1};
    if (scenario == "close" || scenario == "reuse") {
        Require(pipe_nid_postfix(extra) == 0, "second pipe");
        state.descriptors.push_back({extra[0], 1, -1});
    }
    if (scenario == "reuse") Require(pipe_nid_postfix(replacement) == 0, "replacement pipe");
    observed = &state;
    if (signal) Require(sceKernelInstallExceptionHandler(30, reinterpret_cast<void*>(SignalHandler)) == 0, "install signal handler");
    KernelSetPollWaitHookForTest_nid_no_patch(Hook);
    Require(scePthreadKeyCreate(&state.key, reinterpret_cast<pthread_key_destructor_func_t>(Destroy)) == 0, "TSD key");
    const auto started = std::chrono::steady_clock::now();
    Pthread thread = nullptr;
    Require(scePthreadCreate(&thread, nullptr, Poller, &state, nullptr) == 0, "create poller");
    Require(Observe([&] { return state.entered.load(); }), "poller entry");
    const bool immediate = scenario == "zero" || scenario == "invalid";
    if (!state.pending && !immediate) Require(Observe([&] { return state.waiting.load(); }), "poll not admitted to wait");
    const bool race = scenario == "race" || scenario == "close_cancel";
    const bool canceled = scenario == "cancel" || scenario == "pending" || scenario == "disabled" || scenario == "nonblocking";
    if (signal) Require(sceKernelRaiseException(thread, 30) == 0, "interrupt poll with signal");
    else if (race) {
        std::atomic<bool> go{false};
        std::thread requester([&] {
            Require(Observe([&] { return go.load(); }), "release cancellation race");
            Require(pthread_cancel_nid_postfix(thread) == 0, "racing cancellation");
        });
        std::thread completion([&] {
            Require(Observe([&] { return go.load(); }), "release completion race");
            if (scenario == "close_cancel") Require(close_nid_postfix(state.descriptors.front().descriptor) == 0, "racing close");
            else complete();
        });
        go.store(true);
        requester.join();
        completion.join();
    } else if (canceled) {
        Require(pthread_cancel_nid_postfix(thread) == 0, "cancel poller");
        state.release.store(true);
        if (state.disabled && !empty) complete();
    } else if (scenario == "complete" || scenario == "duplicate") {
        complete();
    } else if (scenario == "close") {
        const int input = state.descriptors.front().descriptor;
        Require((net ? sceNetSocketClose(input) : close_nid_postfix(input)) == 0, "close admitted first descriptor");
    } else if (scenario == "reuse") {
        Require(write_nid_postfix(replacement[1], "n", 1) == 1, "seed replacement");
        Require(dup2_nid_postfix(replacement[0], state.descriptors.front().descriptor) == state.descriptors.front().descriptor, "replace admitted descriptor");
    }
    Require(Observe([&] { return thread->_finished.load(); }), "poller did not finish");
    void* result = nullptr;
    Require(scePthreadJoin(thread, &result) == 0, "join poller");
    if (race) Require(result == GUEST_CANCELED || result == reinterpret_cast<void*>(std::uintptr_t{7}), "racing result");
    else Require(result == (canceled ? GUEST_CANCELED : reinterpret_cast<void*>(std::uintptr_t{7})), "thread result");
    Require(state.cleanups.load() == 1 && state.destructors.load() == 1, "cleanup/TSD count");
    if (signal) {
        Require(state.signals.load() == 1, "signal handler count");
        Require(state.result == (state.jumpOnSignal ? -3 : -1), "signal did not interrupt poll");
        if (!state.jumpOnSignal) Require(state.error == 4, "signal interruption errno");
        for (const auto& entry : state.descriptors) Require(entry.revents == -1, "signal copied a partial event set");
        Require(sceKernelRemoveExceptionHandler(30) == 0, "remove signal handler");
    }
    if (scenario == "complete" || scenario == "duplicate") {
        Require(state.result == (scenario == "duplicate" ? 2 : 1), "readiness count");
        for (const auto& entry : state.descriptors) Require(entry.revents == 1, "readiness flags");
    }
    if (scenario == "timeout" || scenario == "zero") Require(state.result == 0, "timeout result");
    if (scenario == "timeout") Require(std::chrono::steady_clock::now() - started >= std::chrono::milliseconds(100), "timeout returned early");
    if (race && result != GUEST_CANCELED) Require(state.result == 1 && state.descriptors.front().revents == (scenario == "race" ? 1 : 0x20), "race lost result");
    if (result == GUEST_CANCELED && !state.disabled)
        for (const auto& entry : state.descriptors) Require(entry.revents == -1, "cancellation copied partial event set");
    if (scenario == "invalid") Require(state.result == 1 && state.descriptors.back().revents == 0x20, "invalid descriptor");
    if (scenario == "close" && net)
        Require(state.result == 1 && (state.descriptors.front().revents & (1 | 0x10 | 0x20)) != 0, "borrowed close must report shutdown or retirement");
    else if (scenario == "close" || scenario == "reuse") Require(state.result >= 1 && state.descriptors.front().revents == 0x20, "closed admission must report POLLNVAL");
    if (scenario == "reuse") {
        char byte = 0;
        Require(read_nid_postfix(state.descriptors.front().descriptor, &byte, 1) == 1 && byte == 'n', "replacement was consumed");
    }
    KernelSetPollWaitHookForTest_nid_no_patch(nullptr);
    Require(scePthreadKeyDelete(state.key) == 0, "delete key");
    if (!empty && scenario != "close" && scenario != "close_cancel") Require(close_nid_postfix(state.descriptors.front().descriptor) == 0, "close input");
    if (state.output >= 0) Require(close_nid_postfix(state.output) == 0, "close output");
    if (replacement[0] >= 0) Require(close_nid_postfix(replacement[0]) == 0 && close_nid_postfix(replacement[1]) == 0, "close replacement pipe");
    if (extra[0] >= 0) Require(close_nid_postfix(extra[0]) == 0 && close_nid_postfix(extra[1]) == 0, "close extra pipe");
}

static std::size_t Resources() {
#ifdef _WIN32
    DWORD count = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &count) != 0, "handle count");
    return count;
#elif defined(__linux__)
    return static_cast<std::size_t>(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{}));
#else
    std::size_t count = 0;
    for (int descriptor = 0; descriptor < getdtablesize(); ++descriptor)
        if (::fcntl(descriptor, F_GETFD) >= 0) ++count;
    return count;
#endif
}

int main(int argc, char** argv) {
    Require(argc == 3, "transport and scenario required");
    std::mutex mutex;
    std::condition_variable changed;
    bool finished = false;
    std::thread watchdog([&] {
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, std::chrono::seconds(8), [&] { return finished; })) {
            std::fprintf(stderr, "poll lifecycle exceeded bounded cleanup deadline\n");
            std::_Exit(2);
        }
    });
    const bool resources = std::string(argv[2]) == "resources";
    if (resources) Run(argv[1], "cancel");
    const auto before = resources ? Resources() : 0;
    const int rounds = resources ? 16 : std::string(argv[2]) == "race" || std::string(argv[2]) == "close_cancel" ? 8 : 1;
    for (int round = 0; round < rounds; ++round) Run(argv[1], resources ? "cancel" : argv[2]);
    if (resources) Require(Resources() <= before + 2, "canceled poll leaked native resources");
    {
        std::lock_guard lock(mutex);
        finished = true;
    }
    changed.notify_one();
    watchdog.join();
}
