#include "prx/libc/include/DescriptorAccess.hpp"

#include <condition_variable>
#include <map>
#include <thread>
#include <limits>
#include <vector>
#include <chrono>

struct GuestDescriptorAccess::State {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned readers = 0;
    unsigned changesWaiting = 0;
    std::thread::id writer;
    unsigned depth = 0;
    std::uint64_t generation = 0;
    bool replacement = false;
    unsigned closesWaiting = 0;
    std::vector<Operation*> operations;

    void Interrupt() noexcept {
        for (auto* operation : operations) operation->Interrupt();
    }

    bool CanRead() const {
        return writer == std::this_thread::get_id() || (writer == std::thread::id{} && changesWaiting == 0);
    }
    bool CanChange() const {
        return writer == std::this_thread::get_id() || (writer == std::thread::id{} && readers == 0);
    }
};

std::shared_ptr<GuestDescriptorAccess::State> GuestDescriptorAccess::Get(int descriptor) {
    static std::mutex mutex;
    static std::map<int, std::weak_ptr<State>> entries;
    std::lock_guard lock(mutex);
    std::erase_if(entries, [](const auto& entry) { return entry.second.expired(); });
    if (auto state = entries[descriptor].lock()) return state;
    auto state = std::make_shared<State>();
    entries[descriptor] = state;
    return state;
}

GuestDescriptorAccess::GuestDescriptorAccess(int descriptor, Mode mode, std::defer_lock_t)
    : state(descriptor < 0 ? nullptr : Get(descriptor)), mode(mode) {}

GuestDescriptorAccess::GuestDescriptorAccess(int descriptor, Mode mode)
    : GuestDescriptorAccess(descriptor, mode, std::defer_lock) { Lock(); }

GuestDescriptorAccess::~GuestDescriptorAccess() { if (held) Unlock(); }

void GuestDescriptorAccess::Lock() {
    if (!state) { held = true; return; }
    std::unique_lock lock(state->mutex);
    if (mode == Mode::Read) {
        state->changed.wait(lock, [&] { return state->CanRead(); });
        ++state->readers;
    } else {
        ++state->changesWaiting;
        if (mode == Mode::Close) ++state->closesWaiting;
        try {
            if (mode == Mode::Close) {
                while (!state->CanChange()) {
                    state->Interrupt();
                    state->changed.wait_for(lock, std::chrono::milliseconds(1));
                }
            } else state->changed.wait(lock, [&] { return state->CanChange(); });
        } catch (...) {
            --state->changesWaiting;
            if (mode == Mode::Close) --state->closesWaiting;
            state->changed.notify_all();
            throw;
        }
        --state->changesWaiting;
        if (mode == Mode::Close) --state->closesWaiting;
        state->writer = std::this_thread::get_id();
        ++state->depth;
        state->replacement = state->replacement || mode == Mode::Change || mode == Mode::Close;
    }
    held = true;
}

bool GuestDescriptorAccess::TryLock() {
    if (!state) { held = true; return true; }
    std::lock_guard lock(state->mutex);
    if (mode == Mode::Read) {
        if (!state->CanRead()) return false;
        ++state->readers;
    } else {
        if (!state->CanChange()) return false;
        state->writer = std::this_thread::get_id();
        ++state->depth;
        state->replacement = state->replacement || mode == Mode::Change || mode == Mode::Close;
    }
    held = true;
    return true;
}

void GuestDescriptorAccess::Unlock() {
    if (!state) { held = false; return; }
    {
        std::lock_guard lock(state->mutex);
        if (mode == Mode::Read) --state->readers;
        else if (--state->depth == 0) {
            state->writer = {};
            if (state->replacement && state->generation != std::numeric_limits<std::uint64_t>::max()) ++state->generation;
            state->replacement = false;
        }
        held = false;
    }
    state->changed.notify_all();
}

bool GuestDescriptorAccess::ReadOrWait() {
    if (!state) { held = true; return true; }
    std::unique_lock lock(state->mutex);
    if (state->CanRead()) {
        ++state->readers;
        held = true;
        return true;
    }
    state->changed.wait(lock);
    return false;
}

void GuestDescriptorAccess::Wake() noexcept { if (state) state->changed.notify_all(); }

GuestDescriptorAccess::Version::Version(std::shared_ptr<State> state, std::uint64_t value)
    : state(std::move(state)), value(value) {}

bool GuestDescriptorAccess::Version::Unchanged() const {
    if (!state) return false;
    std::lock_guard lock(state->mutex);
    return value != std::numeric_limits<std::uint64_t>::max() && state->generation == value && state->closesWaiting == 0;
}

GuestDescriptorAccess::Version GuestDescriptorAccess::Snapshot() const {
    if (!state) return Version(nullptr, 0);
    std::lock_guard lock(state->mutex);
    return Version(state, state->generation);
}

void GuestDescriptorAccess::LockTogether(GuestDescriptorAccess& first, GuestDescriptorAccess& second) {
    struct Lockable {
        GuestDescriptorAccess& access;
        void lock() { access.Lock(); }
        bool try_lock() { return access.TryLock(); }
        void unlock() { access.Unlock(); }
    } firstLock{first}, secondLock{second};
    std::lock(firstLock, secondLock);
}

thread_local GuestDescriptorAccess::Operation* GuestDescriptorAccess::Operation::current = nullptr;

GuestDescriptorAccess::Operation::Operation(GuestDescriptorAccess& access) : state(access.state), previous(current) {
    if (state) {
        std::lock_guard lock(state->mutex);
        state->operations.push_back(this);
        interrupted.store(state->closesWaiting != 0);
    }
    current = this;
}

GuestDescriptorAccess::Operation::~Operation() {
    current = previous;
    if (state) {
        std::lock_guard lock(state->mutex);
        std::erase(state->operations, this);
    }
}

bool GuestDescriptorAccess::Operation::CurrentInterrupted() { return current && current->Interrupted(); }

void GuestDescriptorAccess::Operation::Interrupt() noexcept {
    interrupted.store(true);
    for (auto* registration = wake; registration; registration = registration->previous)
        registration->interrupt(registration->argument);
}

GuestDescriptorAccess::Operation::WakeRegistration::WakeRegistration(void (*interrupt)(void*) noexcept, void* argument)
    : operation(Operation::current), interrupt(interrupt), argument(argument) {
    if (!operation || !operation->state) { operation = nullptr; return; }
    std::lock_guard lock(operation->state->mutex);
    previous = operation->wake;
    operation->wake = this;
}

GuestDescriptorAccess::Operation::WakeRegistration::~WakeRegistration() {
    if (!operation) return;
    std::lock_guard lock(operation->state->mutex);
    operation->wake = previous;
}
