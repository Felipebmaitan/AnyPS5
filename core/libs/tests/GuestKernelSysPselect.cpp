#include "prx/libkernel/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "SceTypes.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <string>
#include <stdexcept>
#ifndef _WIN32
#include <pthread.h>
#include <csignal>
#endif
#include "prx/libkernel/Pthread/include/Pthread.hpp"
#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include "prx/libkernel/System/include/UserContext.hpp"

namespace {

constexpr int Eintr = 4;
constexpr int Efault = 14;
constexpr int Einval = 22;
constexpr int SigBlock = 1;
constexpr int SigSetmask = 3;
constexpr int SigUsr1 = 30;

struct Timespec {
    std::int64_t seconds;
    std::int64_t nanoseconds;
};

struct SignalSet {
    std::uint32_t bits[4]{};
};

struct DescriptorSet {
    std::array<std::uint64_t, 1024 / 64> words{};
    void Add(int descriptor) { words[descriptor / 64] |= std::uint64_t{1} << (descriptor % 64); }
    bool Has(int descriptor) const { return ((words[descriptor / 64] >> (descriptor % 64)) & 1u) != 0; }
};

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "check failed at line %u\n", static_cast<unsigned>(location.line()));
    std::exit(1);
}

int Error() {
    return *__error_nid_postfix();
}

SignalSet CurrentMask() {
    SignalSet current{};
    Require(sigprocmask_nid_postfix(SigBlock, nullptr, &current) == 0);
    return current;
}

bool Same(const SignalSet& left, const SignalSet& right) {
    return std::memcmp(left.bits, right.bits, sizeof(left.bits)) == 0;
}

int caught = 0;

void APS5_VABI Count(int) {
    ++caught;
}

void RaiseBlocked(const SignalSet& blocked) {
    Require(sigprocmask_nid_postfix(SigBlock, &blocked, nullptr) == 0);
    Require(raise_nid_postfix(SigUsr1) == 0 && caught == 0);
}

alignas(16) std::array<std::uint64_t, 12> jumpBuffer{};
SignalSet expectedMask{};
UserUcontext escapeContext{};
bool restoredContext = false;
std::string escapeMode;
int cleanupCount = 0;
int destructorCount = 0;
PthreadKey escapeKey = -1;

void APS5_VABI Escape(int) {
    if (escapeMode == "exception") throw std::runtime_error("pselect handler exception");
    if (escapeMode == "exit") pthread_exit_nid_postfix(reinterpret_cast<void*>(std::uintptr_t{9}));
    if (escapeMode == "context") {
        restoredContext = true;
        setcontext_nid_postfix(&escapeContext);
        Require(false);
    }
    if (escapeMode == "longjmp") longjmp_nid_postfix(jumpBuffer.data(), 1);
    siglongjmp_nid_postfix(jumpBuffer.data(), 1);
}

void APS5_VABI EscapeCleanup(void*) {
    Require(Same(CurrentMask(), expectedMask));
    Require(cleanupCount++ == 0 && destructorCount == 0);
}

void APS5_VABI EscapeDestructor(void*) {
    Require(Same(CurrentMask(), expectedMask));
    Require(cleanupCount == 1 && destructorCount++ == 0);
}

void QueueEscape(const SignalSet& blocked) {
    Require(sigprocmask_nid_postfix(SigSetmask, &blocked, nullptr) == 0);
    Require(raise_nid_postfix(SigUsr1) == 0);
}

void InvokeEscape() {
    const Timespec wait{0, 50000000};
    const SignalSet empty{};
    pselect_nid_postfix(0, nullptr, nullptr, nullptr, &wait, &empty);
    Require(false);
}

void* APS5_VABI EscapeWorker(void*) {
    Require(scePthreadSetspecific(escapeKey, &escapeKey) == 0);
    CleanupHandler cleanup{};
    __pthread_cleanup_push_imp_nid_postfix(EscapeCleanup, nullptr, &cleanup);
    InvokeEscape();
    return nullptr;
}

#ifndef _WIN32
void QueueNativeEscape(int stage) {
    if (stage != 0) return;
    ThreadCancel::KernelSetIoCleanupHookForTest_nid_no_patch(nullptr);
    Require(pthread_kill(pthread_self(), SIGTERM) == 0);
}

int UnblockEscapeTest() {
    escapeMode = "unblock";
    Require(signal_nid_postfix(15, Escape) != reinterpret_cast<GuestHandler>(static_cast<std::uintptr_t>(-1)));
    expectedMask.bits[0] = 1u << (SigUsr1 - 1);
    Require(sigprocmask_nid_postfix(SigSetmask, &expectedMask, nullptr) == 0);
    if (sigsetjmp_nid_postfix(jumpBuffer.data(), 0) == 0) {
        ThreadCancel::KernelSetIoCleanupHookForTest_nid_no_patch(QueueNativeEscape);
        const Timespec zero{};
        const SignalSet empty{};
        pselect_nid_postfix(0, nullptr, nullptr, nullptr, &zero, &empty);
        Require(false);
    }
    Require((CurrentMask().bits[0] & expectedMask.bits[0]) == expectedMask.bits[0]);
    sigset_t native{};
    Require(pthread_sigmask(SIG_BLOCK, nullptr, &native) == 0);
    Require(sigismember(&native, SIGINT) == 0);
    return 0;
}
#endif

int EscapeTest(const std::string& mode) {
    escapeMode = mode;
    Require(signal_nid_postfix(SigUsr1, Escape) != reinterpret_cast<GuestHandler>(static_cast<std::uintptr_t>(-1)));
    SignalSet blocked{};
    blocked.bits[0] = 1u << (SigUsr1 - 1);
    if (mode == "exit") {
        expectedMask = blocked;
        QueueEscape(blocked);
        Require(scePthreadKeyCreate(&escapeKey, reinterpret_cast<pthread_key_destructor_func_t>(EscapeDestructor)) == 0);
        Pthread worker = nullptr;
        Require(scePthreadCreate(&worker, nullptr, EscapeWorker, nullptr, "pselect-exit") == 0);
        void* result = nullptr;
        Require(scePthreadJoin(worker, &result) == 0 && result == reinterpret_cast<void*>(std::uintptr_t{9}));
        Require(cleanupCount == 1 && destructorCount == 1 && Same(CurrentMask(), expectedMask));
        Require(scePthreadKeyDelete(escapeKey) == 0);
        return 0;
    }
    if (mode == "exception") {
        QueueEscape(blocked);
        bool caughtException = false;
        try { InvokeEscape(); } catch (const std::runtime_error&) { caughtException = true; }
        Require(caughtException && Same(CurrentMask(), blocked));
        return 0;
    }
    SignalSet saved{};
    saved.bits[0] = 1u << 31;
    Require(sigprocmask_nid_postfix(SigSetmask, &saved, nullptr) == 0);
    if (mode == "context") {
        Require(getcontext_nid_postfix(&escapeContext) == 0);
        if (!restoredContext) {
            expectedMask = saved;
            blocked.bits[0] |= saved.bits[0];
            QueueEscape(blocked);
            InvokeEscape();
        }
        Require(Same(CurrentMask(), expectedMask));
        return 0;
    }
    const int returned = mode == "longjmp" ? setjmp_nid_postfix(jumpBuffer.data())
        : sigsetjmp_nid_postfix(jumpBuffer.data(), mode == "saved" ? 1 : 0);
    if (returned == 0) {
        blocked.bits[0] |= saved.bits[0];
        expectedMask = mode == "saved" || mode == "longjmp" ? saved : blocked;
        QueueEscape(blocked);
        InvokeEscape();
    }
    Require(returned == 1 && Same(CurrentMask(), expectedMask));
    const Timespec zero{};
    const SignalSet empty{};
    Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, &zero, &empty) == 0);
    Require(Same(CurrentMask(), expectedMask));
    return 0;
}

}

int main(int argc, char** argv) {
#ifndef _WIN32
    if (argc == 2 && std::string(argv[1]) == "unblock") return UnblockEscapeTest();
#endif
    if (argc == 2) return EscapeTest(argv[1]);
    int descriptors[2]{-1, -1};
    Require(pipe_nid_postfix(descriptors) == 0);
    const int reader = descriptors[0];
    const int writer = descriptors[1];
    SignalSet blocked{};
    blocked.bits[(SigUsr1 - 1) / 32] |= 1u << ((SigUsr1 - 1) % 32);
    const SignalSet before = CurrentMask();
    {
        DescriptorSet read{};
        read.Add(reader);
        const Timespec limit{0, 200000000};
        const auto start = std::chrono::steady_clock::now();
        Require(pselect_nid_postfix(reader + 1, read.words.data(), nullptr, nullptr, &limit, &blocked) == 0);
        Require(std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(150));
        Require(!read.Has(reader));
        Require(Same(CurrentMask(), before));
    }
    Require(write_nid_postfix(writer, "x", 1) == 1);
    {
        DescriptorSet read{};
        read.Add(reader);
        const Timespec limit{0, 999999999};
        Require(pselect_nid_postfix(reader + 1, read.words.data(), nullptr, nullptr, &limit, nullptr) == 1);
        Require(read.Has(reader));
    }
    {
        DescriptorSet read{};
        read.Add(reader);
        Require(pselect_nid_postfix(reader + 1, read.words.data(), nullptr, nullptr, nullptr, &blocked) == 1);
        Require(read.Has(reader));
        Require(Same(CurrentMask(), before));
    }
    {
        const Timespec invalid{0, 1000000000};
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, &invalid, &blocked) == -1 && Error() == Einval);
        Require(Same(CurrentMask(), before));
        const Timespec negative{0, -1};
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, &negative, &blocked) == -1 && Error() == Einval);
        Require(Same(CurrentMask(), before));
        const Timespec zero{0, 0};
        Require(pselect_nid_postfix(-1, nullptr, nullptr, nullptr, &zero, nullptr) == -1 && Error() == Einval);
        const auto* unmapped = reinterpret_cast<const void*>(std::uintptr_t{0x10});
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, unmapped, &blocked) == -1 && Error() == Efault);
        Require(Same(CurrentMask(), before));
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, &zero, unmapped) == -1 && Error() == Efault);
        Require(Same(CurrentMask(), before));
    }
    Require(signal_nid_postfix(SigUsr1, Count) != reinterpret_cast<GuestHandler>(static_cast<std::uintptr_t>(-1)));
    const SignalSet empty{};
    {
        RaiseBlocked(blocked);
        const SignalSet withUsr1 = CurrentMask();
        DescriptorSet read{};
        read.Add(writer);
        const DescriptorSet original = read;
        const Timespec limit{0, 300000000};
        const auto start = std::chrono::steady_clock::now();
        Require(pselect_nid_postfix(writer + 1, read.words.data(), nullptr, nullptr, &limit, &empty) == -1 && Error() == Eintr);
        Require(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(150));
        Require(caught == 1);
        Require(read.words == original.words);
        Require(Same(CurrentMask(), withUsr1));
        caught = 0;
    }
    {
        RaiseBlocked(blocked);
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, nullptr, &empty) == -1 && Error() == Eintr && caught == 1);
        caught = 0;
    }
    {
        RaiseBlocked(blocked);
        const Timespec limit{0, 300000000};
        Require(pselect_nid_postfix(1, reinterpret_cast<void*>(std::uintptr_t{0x10}), nullptr, nullptr, &limit, &empty) == -1 && Error() == Efault && caught == 1);
        caught = 0;
    }
    {
        RaiseBlocked(blocked);
        DescriptorSet read{};
        read.Add(reader);
        const Timespec limit{0, 300000000};
        Require(pselect_nid_postfix(reader + 1, read.words.data(), nullptr, nullptr, &limit, &empty) == 1 && caught == 1);
        Require(read.Has(reader));
        caught = 0;
    }
    {
        RaiseBlocked(blocked);
        const Timespec zero{0, 0};
        DescriptorSet read{};
        read.Add(writer);
        Require(pselect_nid_postfix(writer + 1, read.words.data(), nullptr, nullptr, &zero, &empty) == 0 && caught == 1);
        caught = 0;
    }
    {
        RaiseBlocked(blocked);
        const Timespec invalid{0, 1000000000};
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, &invalid, &empty) == -1 && Error() == Einval && caught == 1);
        caught = 0;
    }
    {
        RaiseBlocked(blocked);
        const Timespec limit{0, 200000000};
        const auto start = std::chrono::steady_clock::now();
        Require(pselect_nid_postfix(0, nullptr, nullptr, nullptr, &limit, &blocked) == 0 && caught == 0);
        Require(std::chrono::steady_clock::now() - start >= std::chrono::milliseconds(150));
        Require(sigprocmask_nid_postfix(SigSetmask, &empty, nullptr) == 0 && caught == 1);
        caught = 0;
    }
    Require(sigprocmask_nid_postfix(SigSetmask, &before, nullptr) == 0);
    Require(close_nid_postfix(reader) == 0 && close_nid_postfix(writer) == 0);
    std::puts("pselect passed");
    return 0;
}
