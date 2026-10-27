#include "prx/libkernel/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libkernel/File/include/File.hpp"
#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include "prx/libkernel/Pthread/include/Pthread.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

static void Require(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
}

struct State {
    int input = -1;
    int output = -1;
    PthreadKey key = -1;
    std::string operation;
    bool disabled = false;
    bool pending = false;
    bool sce = false;
    bool partial = false;
    bool waitAll = false;
    std::atomic<bool> ready{false};
    std::atomic<bool> release{false};
    std::atomic<int> cleanups{0};
    std::atomic<int> destructors{0};
    std::atomic<bool> returned{false};
    std::int64_t transferred = -2;
    std::array<char, 4> buffer{};
};

static void APS5_VABI Cleanup(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    Require(state.cleanups.fetch_add(1) == 0, "cleanup repeated");
    Require(state.destructors.load() == 0, "TSD ran before cleanup");
}

static void APS5_VABI Destroy(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    Require(state.cleanups.load() == 1, "cleanup did not precede TSD");
    Require(state.destructors.fetch_add(1) == 0, "TSD repeated");
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

static void* APS5_VABI Reader(void* opaque) {
    auto& state = *static_cast<State*>(opaque);
    if (state.disabled) Require(scePthreadSetcancelstate(GUEST_CANCEL_DISABLE, nullptr) == 0, "disable cancellation");
    Require(scePthreadSetspecific(state.key, &state) == 0, "set TSD");
    CleanupHandler cleanup{};
    __pthread_cleanup_push_imp_nid_postfix(Cleanup, &state, &cleanup);
    state.ready.store(true);
    if (state.pending) Require(Observe([&] { return state.release.load(); }), "release pending reader");
    const std::size_t length = state.partial || state.waitAll ? state.buffer.size() : 1;
    KernelIovec vector{state.buffer.data(), length};
    GuestMsghdr message{};
    message.iov = &vector;
    message.iovLength = 1;
    if (state.operation == "read") state.transferred = read_nid_postfix(state.input, state.buffer.data(), length);
    else if (state.operation == "alias") state.transferred = _read_nid_postfix(state.input, state.buffer.data(), length);
    else if (state.operation == "readv") state.transferred = readv_nid_postfix(state.input, &vector, 1);
    else if (state.operation == "recv") state.transferred = recv_nid_postfix(state.input, state.buffer.data(), length, state.waitAll ? 0x40 : 0);
    else if (state.operation == "recvfrom") state.transferred = recvfrom_nid_postfix(state.input, state.buffer.data(), length, state.waitAll ? 0x40 : 0, nullptr, nullptr);
    else if (state.operation == "recvmsg") state.transferred = recvmsg_nid_postfix(state.input, &message, state.waitAll ? 0x40 : 0);
    else if (state.operation == "sce_read") state.transferred = sceKernelRead(state.input, state.buffer.data(), length);
    else if (state.operation == "sce_readv") state.transferred = sceKernelReadv(state.input, &vector, 1);
    else Require(false, "unknown read API");
    state.returned.store(true);
    if (state.disabled || state.sce) {
        Require(state.transferred == 1 && state.buffer[0] == 'x', "disabled read lost data");
        Require(scePthreadSetcancelstate(GUEST_CANCEL_ENABLE, nullptr) == 0, "enable cancellation");
        scePthreadTestcancel();
    }
    __pthread_cleanup_pop_imp_nid_postfix(1);
    return reinterpret_cast<void*>(std::uintptr_t{7});
}

static void Loopback(State& state) {
    const int listener = socket_nid_postfix(2, 1, 0);
    Require(listener >= 0, "create listener");
    std::array<unsigned char, 16> address{16, 2, 0, 0, 127, 0, 0, 1};
    Require(bind_nid_postfix(listener, address.data(), address.size()) == 0, "bind loopback");
    std::uint32_t size = address.size();
    Require(getsockname_nid_postfix(listener, address.data(), &size) == 0, "get loopback address");
    Require(listen_nid_postfix(listener, 4) == 0, "listen loopback");
    state.output = socket_nid_postfix(2, 1, 0);
    Require(state.output >= 0, "create client");
    Require(connect_nid_postfix(state.output, address.data(), address.size()) == 0, "connect loopback");
    state.input = accept_nid_postfix(listener, nullptr, nullptr);
    Require(state.input >= 0, "accept loopback");
    Require(close_nid_postfix(listener) == 0, "close listener");
}

int main(int argc, char** argv) {
    Require(argc == 4, "expected transport, API, and scenario");
    State state;
    state.operation = argv[2];
    state.sce = state.operation == "sce_read" || state.operation == "sce_readv";
    const std::string scenario = argv[3];
    state.disabled = scenario == "disabled";
    state.pending = scenario == "pending";
    state.partial = scenario == "partial";
    state.waitAll = scenario == "waitall";
    const bool completion = scenario == "complete" || scenario == "reuse_complete" || state.partial;
    const bool reuse = scenario == "reuse" || scenario == "reuse_complete";
    if (std::strcmp(argv[1], "pipe") == 0) {
        int descriptors[2]{};
        Require(pipe_nid_postfix(descriptors) == 0, "create pipe");
        state.input = descriptors[0];
        state.output = descriptors[1];
    } else if (std::strcmp(argv[1], "datagram") == 0) {
        int descriptors[2]{};
        Require(socketpair_nid_postfix(1, 2, 0, descriptors) == 0, "create datagram pair");
        state.input = descriptors[0];
        state.output = descriptors[1];
    } else Loopback(state);
    Require(scePthreadKeyCreate(&state.key, reinterpret_cast<pthread_key_destructor_func_t>(Destroy)) == 0, "create TSD key");
    if (state.waitAll) Require(write_nid_postfix(state.output, "x", 1) == 1, "seed partial WAITALL");
    Pthread reader = nullptr;
    Require(scePthreadCreate(&reader, nullptr, Reader, &state, nullptr) == 0, "create reader");
    Require(Observe([&] { return state.ready.load(); }), "reader did not start");
    if (!state.disabled && !state.pending && !state.sce) {
        const bool registered = Observe([&] {
            std::lock_guard lock(reader->cancelLock);
            return reader->cancelIo != nullptr;
        });
        Require(registered, "read never registered its blocked operation");
    }
    int replacement[2]{-1, -1};
    if (reuse) {
        Require(pipe_nid_postfix(replacement) == 0, "create replacement pipe");
        Require(dup2_nid_postfix(replacement[0], state.input) == state.input, "replace blocked descriptor");
        Require(close_nid_postfix(replacement[0]) == 0, "close replacement source");
        Require(write_nid_postfix(replacement[1], "n", 1) == 1, "seed replacement pipe");
    }
    bool prompt = true;
    if (!completion) {
        std::atomic<bool> canceled{false};
        std::thread requester([&] {
            Require(pthread_cancel_nid_postfix(reader) == 0, "request cancellation");
            canceled.store(true);
        });
        prompt = Observe([&] { return canceled.load(); });
        if (!prompt || state.disabled || state.sce) Require(write_nid_postfix(state.output, "x", 1) == 1, "release failed or disabled read");
        requester.join();
        state.release.store(true);
    } else Require(write_nid_postfix(state.output, "x", 1) == 1, "complete read");
    Require(Observe([&] { return reader->_finished.load(); }), "reader did not exit");
    void* result = nullptr;
    Require(scePthreadJoin(reader, &result) == 0, "join reader");
    Require(prompt, "cancellation required external I/O completion");
    const bool partialCompletion = state.waitAll && result == reinterpret_cast<void*>(std::uintptr_t{7});
    Require(result == (completion || partialCompletion ? reinterpret_cast<void*>(std::uintptr_t{7}) : GUEST_CANCELED), "wrong thread result");
    Require(state.returned.load() == (completion || partialCompletion || state.disabled || state.sce), "unexpected read return");
    if (partialCompletion) Require(state.transferred == 1 && state.buffer[0] == 'x', "interrupted WAITALL lost progress");
    if (completion) Require(state.transferred == 1 && state.buffer[0] == 'x', "completion lost data");
    Require(state.cleanups.load() == 1 && state.destructors.load() == 1, "wrong cleanup or TSD count");
    Require(scePthreadKeyDelete(state.key) == 0, "delete TSD key");
    if (reuse) {
        char byte = 0;
        Require(read_nid_postfix(state.input, &byte, 1) == 1 && byte == 'n', "operation consumed the replacement descriptor");
        Require(close_nid_postfix(replacement[1]) == 0, "close replacement writer");
    }
    Require(close_nid_postfix(state.input) == 0 && close_nid_postfix(state.output) == 0, "close endpoints");
}
