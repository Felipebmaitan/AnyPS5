#ifdef _WIN32
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <unistd.h>
#include <fstream>
#endif
#endif
#include "prx/libkernel/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/DescriptorAccess.hpp"
#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include "prx/libkernel/Pthread/include/Pthread.hpp"
#include "prx/libkernel/Socket/include/SocketRuntime.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static void Require(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "%s (errno %d)\n", message, *__error_nid_postfix());
    std::exit(1);
}

template <class TPredicate>
static bool Observe(TPredicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::yield();
    }
    return true;
}

struct State {
    int socket = -1;
    int result = -2;
    int error = 0;
    int replacement = -1;
    bool disabled = false;
    bool pending = false;
    bool alias = false;
    bool closeOnCleanup = true;
    bool signalReuse = false;
    PthreadKey key = -1;
    std::array<unsigned char, 16> address{16, 2, 0, 0, 127, 0, 0, 1};
    std::atomic<long> nativeThread{0};
    std::atomic<bool> entering{false};
    std::atomic<bool> release{false};
    std::atomic<bool> returned{false};
    std::atomic<int> handlers{0};
    std::atomic<int> cleanups{0};
    std::atomic<int> destructors{0};
};

static State* connecting;

static void APS5_VABI Handler(int, void*) {
    auto& state = *connecting;
    if (state.signalReuse) {
        Require(close_nid_postfix(state.socket) == 0, "handler close");
        Require(dup2_nid_postfix(state.replacement, state.socket) == state.socket, "handler reuse");
    }
    state.handlers.fetch_add(1);
}

static void APS5_VABI Cleanup(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    Require(state.cleanups.fetch_add(1) == 0 && state.destructors.load() == 0, "cleanup order/count");
    if (state.closeOnCleanup) Require(close_nid_postfix(state.socket) == 0, "cleanup connecting socket");
}

static void APS5_VABI Destroy(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    Require(state.cleanups.load() == 1 && state.destructors.fetch_add(1) == 0, "TSD order/count");
}

static void* APS5_VABI Connector(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    if (state.disabled) Require(scePthreadSetcancelstate(GUEST_CANCEL_DISABLE, nullptr) == 0, "disable cancellation");
    Require(scePthreadSetspecific(state.key, &state) == 0, "set TSD");
    CleanupHandler cleanup{};
    __pthread_cleanup_push_imp_nid_postfix(Cleanup, &state, &cleanup);
#ifdef __linux__
    state.nativeThread.store(::syscall(SYS_gettid));
#endif
    state.entering.store(true);
    if (state.pending) Require(Observe([&] { return state.release.load(); }), "pending connector release");
    state.result = state.alias ? _connect_nid_postfix(state.socket, state.address.data(), state.address.size()) :
        connect_nid_postfix(state.socket, state.address.data(), state.address.size());
    state.error = *__error_nid_postfix();
    state.returned.store(true);
    if (state.disabled) {
        Require(state.result == 0, "disabled connection failed");
        Require(scePthreadSetcancelstate(GUEST_CANCEL_ENABLE, nullptr) == 0, "enable cancellation");
        scePthreadTestcancel();
    }
    __pthread_cleanup_pop_imp_nid_postfix(1);
    return reinterpret_cast<void*>(std::uintptr_t{7});
}

int main(int argc, char** argv) {
    Require(argc == 2, "expected scenario");
    const std::string scenario = argv[1];
    const bool refused = scenario == "refused";
    const bool nonblocking = scenario == "nonblocking";
    const bool timeout = scenario == "timeout" || scenario == "no_retransmission";
    const bool signal = scenario == "signal" || scenario == "signal_reuse";
    const bool close = scenario == "close" || scenario == "reuse";
    const bool reuse = scenario == "reuse" || scenario == "signal_reuse";
    const bool keep = scenario == "keep";
    State state;
    connecting = &state;
    state.disabled = scenario == "disabled";
    state.pending = scenario == "pending";
    state.alias = scenario == "alias";
    state.signalReuse = scenario == "signal_reuse";
    state.closeOnCleanup = !close && !reuse && !keep;
    state.socket = socket_nid_postfix(2, 1, 0);
    const int listener = socket_nid_postfix(2, 1, 0);
    Require(state.socket >= 0 && listener >= 0, "create sockets");
    Require(bind_nid_postfix(listener, state.address.data(), state.address.size()) == 0, "bind listener");
    std::uint32_t length = state.address.size();
    Require(getsockname_nid_postfix(listener, state.address.data(), &length) == 0, "listener address");
    std::vector<int> fillers;
    if (!refused) {
        Require(listen_nid_postfix(listener, 1) == 0, "listen");
        Require(fcntl_nid_postfix(listener, 4, 6) == 0, "nonblocking listener");
        for (int index = 0; index < 8; ++index) {
            const int filler = socket_nid_postfix(2, 1, 0);
            Require(filler >= 0 && fcntl_nid_postfix(filler, 4, 6) == 0, "nonblocking filler");
            const int result = connect_nid_postfix(filler, state.address.data(), state.address.size());
            Require(result == 0 || (result == -1 && *__error_nid_postfix() == 36), "fill listener backlog");
            fillers.push_back(filler);
        }
        Require(Observe([&] {
            std::int64_t available = 0;
            bool eof = false;
            return GuestSockets::Ready(listener, false, &available, &eof);
        }), "backlog admission");
    }
    if (nonblocking) Require(fcntl_nid_postfix(state.socket, 4, 6) == 0, "nonblocking connect");
    if (timeout) {
#ifdef _WIN32
        TCP_INITIAL_RTO_PARAMETERS parameters{300, TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS};
        DWORD returned = 0;
        Require(WSAIoctl(static_cast<SOCKET>(GuestSockets::NativeDescriptor(state.socket)), SIO_TCP_INITIAL_RTO,
            &parameters, sizeof(parameters), nullptr, 0, &returned, nullptr, nullptr) == 0, "native connect timeout");
#else
        const timeval duration{0, 100000};
        Require(::setsockopt(static_cast<int>(GuestSockets::NativeDescriptor(state.socket)), SOL_SOCKET, SO_SNDTIMEO,
            &duration, sizeof(duration)) == 0, "native connect timeout");
#endif
    }
    int replacement[2]{-1, -1};
    if (reuse) {
        Require(pipe_nid_postfix(replacement) == 0 && write_nid_postfix(replacement[1], "r", 1) == 1, "replacement pipe");
        state.replacement = replacement[0];
    }
    if (signal) Require(sceKernelInstallExceptionHandler(30, reinterpret_cast<void*>(Handler)) == 0, "install handler");
    Require(scePthreadKeyCreate(&state.key, reinterpret_cast<pthread_key_destructor_func_t>(Destroy)) == 0, "create TSD key");
    const auto wakersBefore = GuestSocketWakerCreationsForTest_nid_no_patch();
    Pthread thread = nullptr;
    Require(scePthreadCreate(&thread, nullptr, Connector, &state, nullptr) == 0, "create connector");
    Require(Observe([&] { return state.entering.load(); }), "connector entry");
    if (!state.pending && !nonblocking && !refused && !timeout) {
        Require(Observe([&] {
#ifdef __linux__
            const auto native = state.nativeThread.load();
            if (!native) return false;
            std::ifstream input("/proc/self/task/" + std::to_string(native) + "/syscall");
            long call = -1;
            std::uint64_t descriptor = 0;
            input >> call >> std::hex >> descriptor;
            return input && call == SYS_connect && descriptor == static_cast<std::uint64_t>(GuestSockets::NativeDescriptor(state.socket));
#else
            if (state.disabled) {
#ifdef _WIN32
                if (GuestSocketWakerCreationsForTest_nid_no_patch() == wakersBefore) return false;
#endif
                GuestDescriptorAccess probe(state.socket, GuestDescriptorAccess::Mode::Change, std::defer_lock);
                return !probe.TryLock();
            }
            std::lock_guard lock(thread->cancelLock);
            return thread->cancelIo != nullptr;
#endif
        }), "blocked connection admission");
        Require(!state.returned.load(), "backlog did not block connect");
    }
    const bool cancel = scenario == "cancel" || state.alias || state.pending || state.disabled || keep;
    if (cancel) Require(pthread_cancel_nid_postfix(thread) == 0, "cancel connector");
    state.release.store(true);
    if (close) {
        Require(close_nid_postfix(state.socket) == 0, "close connecting socket");
        if (reuse) Require(dup2_nid_postfix(replacement[0], state.socket) == state.socket, "reuse connecting slot");
    }
    if (signal) Require(sceKernelRaiseException(thread, 30) == 0, "interrupt connector");
    if (scenario == "complete" || state.disabled) {
        Require(Observe([&] {
            const int accepted = accept_nid_postfix(listener, nullptr, nullptr);
            if (accepted >= 0) Require(close_nid_postfix(accepted) == 0, "drain backlog");
            else Require(*__error_nid_postfix() == 35, "drain listener errno");
            return state.returned.load();
        }), "blocked connection completion");
    }
    Require(Observe([&] { return state.destructors.load() == 1; }), "connector did not retire");
    void* result = nullptr;
    Require(scePthreadJoin(thread, &result) == 0, "join connector");
    Require(result == (cancel ? GUEST_CANCELED : reinterpret_cast<void*>(std::uintptr_t{7})), "connector result");
    Require(state.cleanups.load() == 1 && state.destructors.load() == 1, "cleanup counts");
    if (scenario == "complete") Require(state.result == 0, "connect completion");
    if (nonblocking) Require(state.result == -1 && state.error == 36, "connect in-progress errno");
    if (timeout) {
#ifdef _WIN32
        Require(state.result == -1 && state.error == 61, "native retry-limited connect errno");
#else
        Require(state.result == -1 && state.error == 36, "native connect timeout errno");
#endif
    }
    if (refused) Require(state.result == -1 && state.error == 61, "connection refused errno");
    if (close || signal) Require(state.result == -1 && state.error == 4, "interrupted connect errno");
    if (signal) Require(state.handlers.load() == 1, "handler count");
    if (keep) Require(fcntl_nid_postfix(state.socket, 3) >= 0, "cancellation closed caller socket");
    if (reuse) {
        char byte = 0;
        Require(read_nid_postfix(state.socket, &byte, 1) == 1 && byte == 'r', "connect retirement damaged replacement");
        Require(close_nid_postfix(replacement[0]) == 0 && close_nid_postfix(replacement[1]) == 0, "close replacement pipe");
    }
    if (keep || reuse) Require(close_nid_postfix(state.socket) == 0, "close retained slot");
    for (const int filler : fillers) Require(close_nid_postfix(filler) == 0, "close filler");
    Require(close_nid_postfix(listener) == 0 && scePthreadKeyDelete(state.key) == 0, "release resources");
}
