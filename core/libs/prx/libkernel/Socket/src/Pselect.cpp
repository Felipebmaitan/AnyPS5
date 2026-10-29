#include "prx/libkernel/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include "prx/libkernel/Socket/include/SocketPoll.hpp"

namespace {

constexpr int Eintr = 4;
constexpr int Efault = 14;
constexpr int DescriptorLimit = 1024;

struct Timeval {
    std::int64_t seconds;
    std::int64_t microseconds;
};

using SavedSet = std::array<std::uint64_t, DescriptorLimit / 64>;

bool Save(SavedSet& saved, const void* set, std::size_t bytes) {
    return set == nullptr || GuestCopyIn_nid_no_patch(saved.data(), set, bytes);
}

bool Restore(void* set, const SavedSet& saved, std::size_t bytes) {
    return set == nullptr || GuestCopyOut_nid_no_patch(set, saved.data(), bytes);
}

struct MaskState {
    GuestSignalSet previous{};
    bool armed = false;
};

ThreadCancel::IoCleanup::Completion RestoreMask(void* opaque, bool restored) {
    auto* state = static_cast<MaskState*>(opaque);
    const GuestSignalSet previous = state->previous;
    const bool armed = state->armed;
    delete state;
    if (!armed || restored) return nullptr;
    const int error = *__error_nid_postfix();
    CommitSignalMask_nid_no_patch(&previous);
    *__error_nid_postfix() = error;
    return DeliverSignalMaskPending_nid_no_patch;
}

int Fault() {
    *__error_nid_postfix() = Efault;
    return -1;
}

int ScanAfterCaughtSignal(int nfds, void* readfds, void* writefds, void* exceptfds, const Timeval* wait) {
    const bool validWait = wait == nullptr || (wait->seconds >= 0 && wait->microseconds >= 0 && wait->microseconds < 1000000);
    if (nfds < 0 || nfds > DescriptorLimit || !validWait) return KernelSelect_nid_no_patch(nfds, readfds, writefds, exceptfds, wait);
    const std::size_t bytes = static_cast<std::size_t>((nfds + 63) / 64) * sizeof(std::uint64_t);
    SavedSet read{}, write{}, except{};
    if (!Save(read, readfds, bytes) || !Save(write, writefds, bytes) || !Save(except, exceptfds, bytes)) return Fault();
    const Timeval zero{};
    const int result = KernelSelect_nid_no_patch(nfds, readfds, writefds, exceptfds, &zero);
    if (result != 0 || (wait != nullptr && wait->seconds == 0 && wait->microseconds == 0)) return result;
    if (!Restore(readfds, read, bytes) || !Restore(writefds, write, bytes) || !Restore(exceptfds, except, bytes)) return Fault();
    *__error_nid_postfix() = Eintr;
    return -1;
}

}

extern "C" {

int APS5_VABI pselect_nid_postfix(int nfds, void* readfds, void* writefds, void* exceptfds, const void* timeout, const void* sigmask) {
    ThreadCancel::Check();
    Timeval limit{};
    bool valid = true;
    const Timeval* wait = nullptr;
    if (timeout != nullptr) {
        std::int64_t spec[2]{};
        if (!GuestCopyIn_nid_no_patch(spec, timeout, sizeof(spec))) return Fault();
        valid = spec[0] >= 0 && spec[1] >= 0 && spec[1] < 1000000000;
        limit = {spec[0], spec[1] / 1000};
        wait = &limit;
    }
    auto call = [&](bool caught) {
        return ThreadCancel::Io([&] {
            if (!valid) { *__error_nid_postfix() = 22; return -1; }
            return caught ? ScanAfterCaughtSignal(nfds, readfds, writefds, exceptfds, wait)
                          : KernelSelect_nid_no_patch(nfds, readfds, writefds, exceptfds, wait);
        }, false);
    };
    if (sigmask == nullptr) return call(false);
    GuestSignalSet mask{};
    if (!GuestCopyIn_nid_no_patch(&mask, sigmask, sizeof(mask))) return Fault();
    auto state = std::make_unique<MaskState>();
    ThreadCancel::IoCleanup cleanup(RestoreMask, state.get());
    auto* active = state.release();
    sigprocmask_nid_postfix(1, nullptr, &active->previous);
    active->armed = true;
    const bool caught = SetSignalMaskCatching_nid_no_patch(&mask, &active->previous) != 0;
    return call(caught);
}

}
