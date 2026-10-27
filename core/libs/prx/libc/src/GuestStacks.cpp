#include "prx/libc/include/GuestStacks.hpp"

#include <iterator>
#include <map>
#include <mutex>
#ifdef _WIN32
#include "prx/libc/include/GuestArena.hpp"
#include <windows.h>
#else
#include <pthread.h>
#endif

namespace GuestStacks {
namespace {

std::mutex rangesLock;
std::map<std::uintptr_t, std::uintptr_t> ranges;

Bounds RegisteredRange(std::uintptr_t pointer) {
    std::lock_guard lock(rangesLock);
    const auto next = ranges.upper_bound(pointer);
    if (next == ranges.begin()) return {};
    const auto& [low, high] = *std::prev(next);
    return pointer < high ? Bounds{low, high} : Bounds{};
}

#ifdef _WIN32
struct StackBounds {
    std::uintptr_t base;
    std::uintptr_t limit;
    std::uintptr_t deallocation;
};

constexpr std::size_t DeallocationStackOffset = 0x1478;

StackBounds CurrentBounds() {
    auto* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    auto* teb = reinterpret_cast<std::uint8_t*>(tib);
    return {reinterpret_cast<std::uintptr_t>(tib->StackBase), reinterpret_cast<std::uintptr_t>(tib->StackLimit),
            *reinterpret_cast<std::uintptr_t*>(teb + DeallocationStackOffset)};
}

void ApplyBounds(const StackBounds& bounds) {
    auto* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    auto* teb = reinterpret_cast<std::uint8_t*>(tib);
    tib->StackBase = reinterpret_cast<void*>(bounds.base);
    tib->StackLimit = reinterpret_cast<void*>(bounds.limit);
    *reinterpret_cast<std::uintptr_t*>(teb + DeallocationStackOffset) = bounds.deallocation;
}

bool RegisteredBounds(std::uintptr_t stackPointer, StackBounds& bounds) {
    const auto range = RegisteredRange(stackPointer);
    if (!range.Contains(stackPointer)) return false;
    bounds = {range.high, range.low, range.low};
    return true;
}

bool HostBounds(std::uintptr_t stackPointer, StackBounds& bounds) {
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQuery(reinterpret_cast<const void*>(stackPointer), &memory, sizeof(memory)) != sizeof(memory) || memory.State != MEM_COMMIT) return false;
    const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
    bounds = {base + memory.RegionSize, base, reinterpret_cast<std::uintptr_t>(memory.AllocationBase)};
    return true;
}
#endif

}

void GuestStackRegister_nid_no_patch(const void* pointer, std::size_t bytes) {
    const auto low = reinterpret_cast<std::uintptr_t>(pointer);
    const auto high = low + bytes;
    std::lock_guard lock(rangesLock);
    const auto same = ranges.find(low);
    if (same != ranges.end() && same->second == high) return;
    auto overlap = ranges.upper_bound(low);
    if (overlap != ranges.begin() && std::prev(overlap)->second > low) --overlap;
    while (overlap != ranges.end() && overlap->first < high) {
#ifdef _WIN32
        GuestArena::GuestArenaUnpinWritable_nid_postfix(reinterpret_cast<const void*>(overlap->first), overlap->second - overlap->first);
#endif
        overlap = ranges.erase(overlap);
    }
#ifdef _WIN32
    GuestArena::GuestArenaPinWritable_nid_postfix(pointer, bytes);
#endif
    ranges.emplace(low, high);
}

Bounds GuestStackBounds_nid_no_patch(std::uintptr_t stackPointer) {
    const auto registered = RegisteredRange(stackPointer);
    if (registered.Contains(stackPointer)) return registered;
#ifdef _WIN32
    const auto native = CurrentBounds();
    return {native.deallocation, native.base};
#elif defined(__APPLE__)
    const auto high = reinterpret_cast<std::uintptr_t>(pthread_get_stackaddr_np(pthread_self()));
    return {high - pthread_get_stacksize_np(pthread_self()), high};
#else
    pthread_attr_t attributes;
    if (pthread_getattr_np(pthread_self(), &attributes) != 0) return {};
    void* pointer = nullptr;
    std::size_t bytes = 0;
    const int result = pthread_attr_getstack(&attributes, &pointer, &bytes);
    pthread_attr_destroy(&attributes);
    if (result != 0) return {};
    const auto low = reinterpret_cast<std::uintptr_t>(pointer);
    return {low, low + bytes};
#endif
}

void APS5_VABI GuestStackSwitch_nid_no_patch(std::uintptr_t stackPointer) {
#ifdef _WIN32
    const auto current = CurrentBounds();
    if (stackPointer >= current.deallocation && stackPointer < current.base) return;
    StackBounds target{};
    if (RegisteredBounds(stackPointer, target) || HostBounds(stackPointer, target)) ApplyBounds(target);
#else
    (void)stackPointer;
#endif
}

}
