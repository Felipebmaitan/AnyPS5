#include "prx/libkernel/include/Api.hpp"
#include "prx/libkernel/Equeue/Equeue.hpp"
#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include "prx/libkernel/Pthread/include/Pthread.hpp"
#include "prx/libkernel/Socket/include/SocketRuntime.hpp"
#include "prx/libc/include/Api.hpp"
#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
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
    int queue = -1;
    int input = -1;
    int output = -1;
    int nested = -1;
    PthreadKey key = -1;
    KernelEvent event{987};
    KernelEvent change{};
    KernelTimespec timeout{2, 0};
    bool infinite = true;
    bool disabled = false;
    bool pending = false;
    bool noEvents = false;
    bool changes = false;
    bool throwInWait = false;
    bool gateNative = false;
    bool gateSnapshot = false;
    bool gateScan = false;
    std::atomic<bool> scanPaused{false};
    std::atomic<int> admissions{0};
    bool testAfter = false;
    bool signalJump = false;
    bool timeoutCancel = false;
    KernelEqueue legacy = 0;
    std::atomic<bool> expired{false};
    int result = -2;
    int error = 0;
    std::atomic<bool> entered{false};
    std::atomic<bool> released{false};
    std::atomic<bool> waiting{false};
    std::atomic<bool> native{false};
    std::atomic<bool> returned{false};
    std::atomic<int> cleanups{0};
    std::atomic<int> destructors{0};
    std::atomic<int> signals{0};
    alignas(16) std::array<std::uint64_t, 12> jump{};
#ifdef __linux__
    std::atomic<long> nativeId{0};
#endif
};
static State* observed = nullptr;
static void Hook(int stage) {
    auto& state = *observed;
    if (stage == 0) state.waiting.store(true);
    if (stage == 4 && state.gateScan && state.native.load() && !state.scanPaused.exchange(true))
        Require(Observe([&] { return state.released.load(); }), "release descriptor scan");
    if (stage == 2 && state.timeoutCancel) {
        state.expired.store(true);
        Require(Observe([&] { return state.released.load(); }), "release expired wait");
    }
    if (stage == 3 && state.gateSnapshot) {
        state.native.store(true);
        Require(Observe([&] { return state.released.load(); }), "release gathered kevent descriptors");
    }
    if (stage == 1) {
        state.admissions.fetch_add(1);
        state.native.store(true);
        if (state.gateNative) Require(Observe([&] { return state.released.load(); }), "release admitted kevent wait");
        if (state.throwInWait) throw std::runtime_error("kevent test interruption");
    }
}
static void APS5_VABI Signal(int, void*) {
    observed->signals.fetch_add(1);
    if (observed->signalJump) longjmp_nid_postfix(observed->jump.data(), 1);
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
static void* APS5_VABI Waiter(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    if (state.disabled) Require(scePthreadSetcancelstate(GUEST_CANCEL_DISABLE, nullptr) == 0, "disable cancellation");
    Require(scePthreadSetspecific(state.key, &state) == 0, "set TSD");
    CleanupHandler cleanup{};
    __pthread_cleanup_push_imp_nid_postfix(Cleanup, &state, &cleanup);
#ifdef __linux__
    state.nativeId.store(::syscall(SYS_gettid));
#endif
    state.entered.store(true);
    if (state.pending) Require(Observe([&] { return state.released.load(); }), "release pending request");
    if (state.signalJump && setjmp_nid_postfix(state.jump.data()) != 0) state.result = -3;
    else {
        try {
            if (state.legacy != 0) {
                int count = -1;
                const std::uint32_t timeout = 1000;
                state.result = sceKernelWaitEqueue(state.legacy, &state.event, 1, &count, &timeout);
            } else state.result = kevent_nid_postfix(state.queue, state.changes ? &state.change : nullptr, state.changes ? 1 : 0,
                &state.event, state.noEvents ? 0 : 1, state.infinite ? nullptr : &state.timeout);
        } catch (const std::runtime_error&) {
            if (!state.throwInWait) throw;
            state.result = -4;
        }
    }
    state.error = *__error_nid_postfix();
    state.returned.store(true);
    if (state.disabled) {
        Require(Observe([&] { return state.released.load(); }), "cancellation requested before enabling");
        Require(scePthreadSetcancelstate(GUEST_CANCEL_ENABLE, nullptr) == 0, "enable cancellation");
        scePthreadTestcancel();
    }
    if (state.testAfter) scePthreadTestcancel();
    __pthread_cleanup_pop_imp_nid_postfix(1);
    return reinterpret_cast<void*>(std::uintptr_t{7});
}

static void Add(int queue, std::uintptr_t ident, std::int16_t filter, std::uint16_t flags = EV_ADD) {
    const KernelEvent change{ident, filter, flags};
    Require(kevent_nid_postfix(queue, &change, 1, nullptr, 0, nullptr) == 0, "register event");
}
static void Trigger(int queue) {
    const KernelEvent change{41, EVFILT_USER, 0, 0x01000000};
    Require(kevent_nid_postfix(queue, &change, 1, nullptr, 0, nullptr) == 0, "trigger user event");
}
static void Pair(State& state) {
    const int listener = socket_nid_postfix(2, 1, 0);
    Require(listener >= 0, "listener");
    std::array<unsigned char, 16> address{16, 2, 0, 0, 127, 0, 0, 1};
    Require(bind_nid_postfix(listener, address.data(), address.size()) == 0, "bind");
    std::uint32_t size = address.size();
    Require(getsockname_nid_postfix(listener, address.data(), &size) == 0 && listen_nid_postfix(listener, 2) == 0, "listen");
    state.input = socket_nid_postfix(2, 1, 0);
    Require(state.input >= 0 && connect_nid_postfix(state.input, address.data(), address.size()) == 0, "connect");
    state.output = accept_nid_postfix(listener, nullptr, nullptr);
    Require(state.output >= 0 && close_nid_postfix(listener) == 0, "accept");
}
static void Complete(State& state) {
    if (state.output >= 0) Require(write_nid_postfix(state.output, "k", 1) == 1, "make descriptor ready");
    else Trigger(state.nested >= 0 ? state.nested : state.queue);
}
static void Run(const std::string& transport, const std::string& scenario) {
    State state;
    observed = &state;
    state.queue = kqueue_nid_postfix();
    Require(state.queue >= 0, "create kqueue");
    const bool descriptor = transport == "pipe" || transport == "tcp" || transport == "nested_pipe";
    if (transport == "pipe" || transport == "nested_pipe") {
        int pair[2];
        Require(pipe_nid_postfix(pair) == 0, "pipe");
        state.input = pair[0]; state.output = pair[1];
    } else if (transport == "tcp") Pair(state);
    if (transport == "nested_pipe") {
        state.nested = kqueue_nid_postfix();
        Require(state.nested >= 0, "nested descriptor queue");
        Add(state.nested, state.input, EVFILT_READ, EV_ADD | EV_ONESHOT);
        Add(state.queue, state.nested, EVFILT_READ, EV_ADD | EV_ONESHOT);
    } else if (descriptor) Add(state.queue, state.input, EVFILT_READ, EV_ADD | EV_ONESHOT);
    else if (transport == "nested") {
        state.nested = kqueue_nid_postfix();
        Require(state.nested >= 0, "nested queue");
        Add(state.nested, 41, EVFILT_USER, EV_ADD | EV_ONESHOT);
        Add(state.queue, state.nested, EVFILT_READ, EV_ADD | EV_ONESHOT);
    } else if (transport != "empty") Add(state.queue, 41, EVFILT_USER, EV_ADD | EV_ONESHOT);
    state.disabled = scenario == "disabled";
    state.pending = scenario == "pending" || scenario == "noevents" || scenario == "changes_pending" || scenario == "legacy";
    state.noEvents = scenario == "noevents";
    state.changes = scenario == "changes" || scenario == "noevents" || scenario == "changes_pending";
    state.change = KernelEvent{73, EVFILT_USER, EV_ADD};
    state.testAfter = scenario == "noevents" || scenario == "changes" || scenario == "timeout_cancel" || scenario == "legacy";
    state.throwInWait = scenario == "exception";
    state.gateNative = scenario == "watched_reuse";
    state.timeoutCancel = scenario == "timeout_cancel";
    if (scenario == "legacy") Require(sceKernelCreateEqueue(&state.legacy, "legacy") == 0, "create SCE equeue");
    state.gateSnapshot = scenario == "snapshot_reuse";
    state.gateScan = scenario == "scan_reuse";
    state.signalJump = scenario == "signal_jump";
    if ((scenario == "timeout" || state.timeoutCancel) || (state.disabled && transport == "empty")) { state.infinite = false; state.timeout = {0, 50000000}; }
    if (scenario == "zero" || scenario == "invalid" || scenario == "badtime") { state.infinite = false; state.timeout = {0, 0}; }
    if (scenario == "badtime") state.timeout.tv_nsec = 1000000000;
    std::optional<GuestDescriptorAccess> admission;
    if (scenario == "admission") admission.emplace(state.input, GuestDescriptorAccess::Mode::Update);
    const int originalQueue = state.queue;
    if (scenario == "invalid") state.queue = -1;
    if (scenario == "signal" || state.signalJump) Require(sceKernelInstallExceptionHandler(30, reinterpret_cast<void*>(Signal)) == 0, "install signal handler");
    KernelSetKeventWaitHookForTest_nid_no_patch(Hook);
    Require(scePthreadKeyCreate(&state.key, reinterpret_cast<pthread_key_destructor_func_t>(Destroy)) == 0, "create key");
    Pthread thread = nullptr;
    Require(scePthreadCreate(&thread, nullptr, Waiter, &state, "kevent-cancel") == 0, "create waiter");
    Require(Observe([&] { return state.entered.load(); }), "observe waiter entry");
    const bool immediate = scenario == "zero" || scenario == "invalid" || scenario == "badtime";
    if (!state.pending && !immediate) Require(Observe([&] { return state.waiting.load(); }), "observe kevent wait");
#ifdef __linux__
    if (scenario == "admission") Require(Observe([&] {
        std::ifstream input("/proc/self/task/" + std::to_string(state.nativeId.load()) + "/syscall");
        long call = -1; input >> call;
        return input && call == SYS_futex;
    }), "observe blocked descriptor admission");
    if ((scenario == "cancel" || scenario == "signal" || state.signalJump) && descriptor) Require(Observe([&] {
        std::ifstream input("/proc/self/task/" + std::to_string(state.nativeId.load()) + "/syscall");
        long call = -1; input >> call;
        return input && call == SYS_ppoll;
    }), "observe blocked native kevent");
#endif
    bool queueClosed = false;
    int replacement[2]{-1, -1};
    if (state.timeoutCancel) {
        Require(Observe([&] { return state.expired.load(); }), "observe timeout selection");
        std::thread requester([&] { Require(pthread_cancel_nid_postfix(thread) == 0, "cancel expired wait"); });
        Require(Observe([&] { return thread->cancelPending.load(); }), "observe request before returning timeout");
        state.released.store(true); requester.join();
    } else if (state.pending || scenario == "cancel" || scenario == "admission" || state.disabled || scenario == "changes") {
        Require(pthread_cancel_nid_postfix(thread) == 0, "request cancellation");
        state.released.store(true);
        if (state.disabled && transport != "empty") Complete(state);
    } else if (scenario == "complete") Complete(state);
    else if (scenario == "signal" || state.signalJump) Require(sceKernelRaiseException(thread, 30) == 0, "raise exception");
    else if (scenario == "close" || scenario == "queue_reuse") {
        Require(close_nid_postfix(state.queue) == 0, "close waiting queue");
        queueClosed = true;
        if (scenario == "queue_reuse") {
            const int next = kqueue_nid_postfix();
            Require(next == originalQueue, "reuse queue number");
            Add(next, 41, EVFILT_USER); Trigger(next);
            KernelEvent event{}; const KernelTimespec zero{};
            Require(kevent_nid_postfix(next, nullptr, 0, &event, 1, &zero) == 1 && event.ident == 41, "replacement queue event intact");
            Require(close_nid_postfix(next) == 0, "close replacement queue");
        }
    } else if (state.gateScan) {
#ifdef __linux__
        Require(Observe([&] { return state.native.load(); }), "observe first descriptor wait");
        Add(state.queue, 91, EVFILT_USER);
        Require(Observe([&] { return state.scanPaused.load(); }), "pause readiness scan with queue locked");
        Require(pipe_nid_postfix(replacement) == 0, "scan replacement pipe");
        Require(write_nid_postfix(replacement[1], "r", 1) == 1, "seed scan replacement");
        struct stat original{};
        Require(::fstat(replacement[0], &original) == 0, "replacement identity");
        std::thread replacing([&] { Require(dup2_nid_postfix(replacement[0], state.input) == state.input, "replace before note removal"); });
        Require(Observe([&] {
            struct stat current{};
            return ::fstat(state.input, &current) == 0 && current.st_dev == original.st_dev && current.st_ino == original.st_ino;
        }), "observe native replacement before queue note removal");
        state.released.store(true); replacing.join();
        Require(!state.returned.load(), "scan used newly replaced native descriptor");
        Require(pthread_cancel_nid_postfix(thread) == 0, "cancel after scan retirement");
#endif
    } else if (scenario == "watched_reuse" || scenario == "snapshot_reuse") {
        Require(Observe([&] { return state.native.load(); }), "observe descriptor admission");
        Require(pipe_nid_postfix(replacement) == 0, "replacement pipe");
        Require(write_nid_postfix(replacement[1], "r", 1) == 1, "seed replacement");
        std::atomic<bool> done{false};
        std::thread replacing([&] {
            Require(dup2_nid_postfix(replacement[0], state.input) == state.input, "replace watched descriptor");
            done.store(true);
        });
        GuestDescriptorAccess probe(state.input, GuestDescriptorAccess::Mode::Read, std::defer_lock);
        if (state.gateSnapshot) {
            Require(Observe([&] { return done.load(); }), "replace gathered descriptor before admission");
        } else Require(Observe([&] { if (!probe.TryLock()) return true; probe.Unlock(); return false; }), "replacement waiting for admission");
        state.released.store(true);
        Require(Observe([&] { return done.load(); }), "replacement drains admitted wait");
        replacing.join();
        Require(!state.returned.load(), "retired knote reported replacement readiness");
        Require(pthread_cancel_nid_postfix(thread) == 0, "cancel after descriptor replacement");
    } else if (scenario == "race") {
        std::atomic<bool> go{false};
        std::thread cancel([&] { Require(Observe([&] { return go.load(); }), "race start"); Require(pthread_cancel_nid_postfix(thread) == 0, "race cancellation"); });
        go.store(true); Complete(state); cancel.join();
    }
    const bool prompt = Observe([&] { return thread->_finished.load(); });
    if (!prompt && !queueClosed) { close_nid_postfix(state.queue); queueClosed = true; }
    Require(Observe([&] { return thread->_finished.load(); }), "bounded kevent cleanup");
    void* result = nullptr;
    Require(scePthreadJoin(thread, &result) == 0, "join waiter");
    Require(prompt, "kevent did not complete promptly");
    const bool canceled = scenario == "cancel" || scenario == "admission" || state.pending || state.disabled || scenario == "changes" || scenario == "watched_reuse" || scenario == "snapshot_reuse" || state.timeoutCancel || state.gateScan;
    if (scenario == "race") Require(result == GUEST_CANCELED || (state.result == 1 && state.event.ident != 987), "race completion");
    else Require(result == (canceled ? GUEST_CANCELED : reinterpret_cast<void*>(std::uintptr_t{7})), "waiter exit result");
    Require(state.cleanups.load() == 1 && state.destructors.load() == 1, "cleanup and TSD exactly once");
    if (result == GUEST_CANCELED && !state.disabled) Require(state.event.ident == 987, "cancellation modified output");
    if (scenario == "race" && result == GUEST_CANCELED) {
        KernelEvent remaining{}; const KernelTimespec limit{1, 0};
        Require(kevent_nid_postfix(originalQueue, nullptr, 0, &remaining, 1, &limit) == 1, "cancellation consumed an unreported one-shot event");
    }
    if (state.gateSnapshot) Require(state.admissions.load() == 0, "native wait admitted a stale gathered descriptor");
    if (state.timeoutCancel) Require(state.returned.load() && state.result == 0, "timeout result lost to late cancellation");
    if (state.legacy != 0) {
        Require(state.returned.load() && state.result == SCE_KERNEL_ERROR_ETIMEDOUT, "SCE wait consumed POSIX cancellation");
        Require(sceKernelDeleteEqueue(state.legacy) == 0, "delete SCE equeue");
    }
    if (scenario == "noevents") Require(state.returned.load() && state.result == 0, "nevents zero consumed cancellation");
    if (scenario == "changes") Require(state.returned.load() && state.result == -1 && state.error == 4, "applied changes consumed cancellation before returning EINTR");
    if (scenario == "changes" || scenario == "noevents" || scenario == "changes_pending") {
        const KernelEvent remove{73, EVFILT_USER, EV_DELETE};
        const int removed = kevent_nid_postfix(originalQueue, &remove, 1, nullptr, 0, nullptr);
        Require(removed == (scenario == "changes_pending" ? -1 : 0), "change list application contract");
    }
    if (scenario == "complete") Require(state.result == 1 && state.event.ident == static_cast<std::uintptr_t>(state.nested >= 0 ? state.nested : descriptor ? state.input : 41), "ready event");
    if (scenario == "timeout" || scenario == "zero") Require(state.result == 0 && state.event.ident == 987, "timeout output");
    if (scenario == "invalid" || scenario == "close" || scenario == "queue_reuse") Require(state.result == -1 && state.error == 9, "queue ownership error");
    if (scenario == "badtime") Require(state.result == -1 && state.error == 22, "timespec validation");
    if (scenario == "exception") Require(state.result == -4, "exception propagated");
    if (scenario == "signal" || state.signalJump) {
        Require(state.signals.load() == 1 && state.result == (state.signalJump ? -3 : -1), "signal delivery result");
        Require(sceKernelRemoveExceptionHandler(30) == 0, "remove signal handler");
    }
    if (scenario == "watched_reuse" || scenario == "snapshot_reuse" || state.gateScan) {
        char byte = 0;
        Require(read_nid_postfix(state.input, &byte, 1) == 1 && byte == 'r', "replacement data intact");
    }
    KernelSetKeventWaitHookForTest_nid_no_patch(nullptr);
    admission.reset();
    if (!queueClosed) Require(close_nid_postfix(originalQueue) == 0, "close queue");
    for (const int fd : {state.input, state.output, state.nested, replacement[0], replacement[1]})
        if (fd >= 0) Require(close_nid_postfix(fd) == 0, "close fixture descriptor");
    Require(scePthreadKeyDelete(state.key) == 0, "delete key");
}

static void Capacity(const std::string& scenario) {
    State state;
    observed = &state;
    state.queue = kqueue_nid_postfix();
    Require(state.queue >= 0, "capacity queue");
    KernelEvent warm{};
    const KernelTimespec zero{};
    Require(kevent_nid_postfix(state.queue, nullptr, 0, &warm, 1, &zero) == 0, "initialize shared I/O state");
    if (scenario == "ready") { Add(state.queue, 41, EVFILT_USER, EV_ADD | EV_ONESHOT); Trigger(state.queue); }
    state.pending = true;
    if (scenario == "timeout") { state.infinite = false; state.timeout = {0, 20000000}; }
    KernelSetKeventWaitHookForTest_nid_no_patch(Hook);
    Require(scePthreadKeyCreate(&state.key, reinterpret_cast<pthread_key_destructor_func_t>(Destroy)) == 0, "capacity key");
    Pthread thread = nullptr;
    Require(scePthreadCreate(&thread, nullptr, Waiter, &state, "kevent-capacity") == 0, "capacity waiter");
    Require(Observe([&] { return state.entered.load(); }), "capacity waiter initialized");
    const auto wakers = GuestSocketWakerCreationsForTest_nid_no_patch();
#ifdef __linux__
    rlimit previous{};
    Require(::getrlimit(RLIMIT_NOFILE, &previous) == 0, "descriptor limit");
    auto limited = previous;
    limited.rlim_cur = std::min<rlim_t>(previous.rlim_cur, 64);
    Require(::setrlimit(RLIMIT_NOFILE, &limited) == 0, "bound descriptor limit");
    std::vector<int> occupied;
    for (;;) {
        const int descriptor = ::open("/dev/null", O_RDONLY);
        if (descriptor < 0) break;
        occupied.push_back(descriptor);
    }
    Require(errno == EMFILE, "exhaust process descriptors");
#endif
    state.released.store(true);
    if (scenario == "cancel") {
        Require(Observe([&] { return state.waiting.load(); }), "capacity condition wait");
        Require(pthread_cancel_nid_postfix(thread) == 0, "cancel under descriptor pressure");
    }
    const bool prompt = Observe([&] { return thread->_finished.load(); });
#ifdef __linux__
    for (const int descriptor : occupied) ::close(descriptor);
    Require(::setrlimit(RLIMIT_NOFILE, &previous) == 0, "restore descriptor limit");
#endif
    if (!prompt) close_nid_postfix(state.queue);
    Require(Observe([&] { return thread->_finished.load(); }), "capacity failure cleanup");
    void* result = nullptr;
    Require(scePthreadJoin(thread, &result) == 0 && prompt, "capacity waiter completed");
    Require(result == (scenario == "cancel" ? GUEST_CANCELED : reinterpret_cast<void*>(std::uintptr_t{7})), "capacity cancellation result");
    if (scenario != "cancel") Require(state.result == (scenario == "ready" ? 1 : 0), "capacity kevent result");
    Require(GuestSocketWakerCreationsForTest_nid_no_patch() == wakers, "condition-only kevent created a native wake socket");
    Require(state.cleanups.load() == 1 && state.destructors.load() == 1, "capacity cleanup and TSD");
    KernelSetKeventWaitHookForTest_nid_no_patch(nullptr);
    Require(close_nid_postfix(state.queue) == 0 && scePthreadKeyDelete(state.key) == 0, "capacity resources");
}

static std::size_t Resources() {
#ifdef _WIN32
    DWORD count = 0;
    Require(GetProcessHandleCount(GetCurrentProcess(), &count) != 0, "handle count");
    return count;
#elif defined(__linux__)
    return static_cast<std::size_t>(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{}));
#else
    return 0;
#endif
}

int main(int argc, char** argv) {
    Require(argc == 3, "transport and scenario required");
    std::mutex mutex; std::condition_variable changed; bool done = false;
    std::thread watchdog([&] {
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, std::chrono::seconds(10), [&] { return done; })) {
            std::fprintf(stderr, "kevent lifecycle exceeded cleanup bound\n"); std::_Exit(2);
        }
    });
    const bool resources = std::string(argv[2]) == "resources";
    if (resources) Run(argv[1], "cancel");
    const auto before = resources ? Resources() : 0;
    const int rounds = resources ? 16 : std::string(argv[2]) == "race" ? 8 : 1;
    for (int i = 0; i < rounds; ++i) {
        if (std::string(argv[1]) == "capacity") Capacity(argv[2]);
        else Run(argv[1], resources ? "cancel" : argv[2]);
    }
    if (resources) Require(Resources() <= before + 2, "canceled kevent leaked resources");
    { std::lock_guard lock(mutex); done = true; }
    changed.notify_one(); watchdog.join();
}
