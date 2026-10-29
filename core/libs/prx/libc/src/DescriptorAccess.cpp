#include "prx/libc/include/DescriptorAccess.hpp"

#include <condition_variable>
#include <map>
#include <thread>
#include <limits>
#include <vector>
#include <chrono>

namespace {
std::atomic<void (*)(int)> publicationWaitHook{nullptr};
}

void DescriptorAccessSetPublicationWaitHookForTest_nid_no_patch(void (*hook)(int)) {
    publicationWaitHook.store(hook);
}

struct GuestDescriptorAccess::State {
    int descriptor;
    explicit State(int descriptor) : descriptor(descriptor) {}
    std::mutex mutex;
    std::condition_variable changed;
    std::mutex wakeMutex;
    std::condition_variable wakeChanged;
    std::uint64_t revision = 0;
    unsigned readers = 0;
    unsigned changesWaiting = 0;
    std::thread::id writer;
    unsigned depth = 0;
    std::uint64_t generation = 0;
    bool replacement = false;
    unsigned closesWaiting = 0;
    unsigned replacementsWaiting = 0;
    std::vector<Operation*> operations;

    void Notify() noexcept {
        {
            std::lock_guard lock(wakeMutex);
            ++revision;
        }
        wakeChanged.notify_all();
        changed.notify_all();
    }

    void Interrupt(bool closing = true) noexcept {
        for (auto* operation : operations)
            if (closing || operation->retireOnReplace) operation->Interrupt();
    }

    void Refresh() noexcept {
        for (auto* operation : operations)
            if (operation->retireOnReplace) operation->Refresh();
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
    auto state = std::make_shared<State>(descriptor);
    entries[descriptor] = state;
    return state;
}

void DescriptorAccessInitialize_nid_no_patch(void* access, int descriptor) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    self.state = descriptor < 0 ? nullptr : GuestDescriptorAccess::Get(descriptor);
}

void DescriptorAccessLock_nid_no_patch(void* access) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) { self.held = true; return; }
    const bool closing = self.mode == GuestDescriptorAccess::Mode::Close || self.mode == GuestDescriptorAccess::Mode::Publish;
    std::unique_lock lock(self.state->mutex);
    if (self.mode == GuestDescriptorAccess::Mode::Read) {
        self.state->changed.wait(lock, [&] { return self.state->CanRead(); });
        ++self.state->readers;
    } else {
        ++self.state->changesWaiting;
        if (closing) ++self.state->closesWaiting;
        if (self.mode == GuestDescriptorAccess::Mode::Replace) ++self.state->replacementsWaiting;
        try {
            if (self.mode == GuestDescriptorAccess::Mode::Publish && !self.state->CanChange())
                if (const auto hook = publicationWaitHook.load()) hook(self.state->descriptor);
            if (self.mode == GuestDescriptorAccess::Mode::Retire) {
                self.state->changed.wait(lock, [&] {
                    return self.state->writer == std::thread::id{} || self.state->writer == std::this_thread::get_id();
                });
            } else if (closing || self.mode == GuestDescriptorAccess::Mode::Replace) {
                while (!self.state->CanChange()) {
                    self.state->Interrupt(closing);
                    self.state->changed.wait_for(lock, std::chrono::milliseconds(1));
                }
            } else if (self.mode == GuestDescriptorAccess::Mode::Update) {
                while (!self.state->CanChange()) {
                    self.state->Refresh();
                    self.state->changed.wait_for(lock, std::chrono::milliseconds(1));
                }
            } else self.state->changed.wait(lock, [&] { return self.state->CanChange(); });
        } catch (...) {
            --self.state->changesWaiting;
            if (closing) --self.state->closesWaiting;
            if (self.mode == GuestDescriptorAccess::Mode::Replace) --self.state->replacementsWaiting;
            self.state->Notify();
            throw;
        }
        --self.state->changesWaiting;
        if (closing) --self.state->closesWaiting;
        if (self.mode == GuestDescriptorAccess::Mode::Replace) --self.state->replacementsWaiting;
        self.state->writer = std::this_thread::get_id();
        ++self.state->depth;
        self.state->replacement = self.state->replacement || self.mode == GuestDescriptorAccess::Mode::Change || closing || self.mode == GuestDescriptorAccess::Mode::Replace;
    }
    self.held = true;
}

bool DescriptorAccessTryLock_nid_no_patch(void* access) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) { self.held = true; return true; }
    std::lock_guard lock(self.state->mutex);
    if (self.mode == GuestDescriptorAccess::Mode::Read) {
        if (!self.state->CanRead()) return false;
        ++self.state->readers;
    } else {
        const bool canChange = self.mode == GuestDescriptorAccess::Mode::Retire ?
            self.state->writer == std::thread::id{} || self.state->writer == std::this_thread::get_id() : self.state->CanChange();
        if (!canChange) {
            if (self.mode == GuestDescriptorAccess::Mode::Update) self.state->Refresh();
            if (self.mode == GuestDescriptorAccess::Mode::Replace || self.mode == GuestDescriptorAccess::Mode::Publish)
                self.state->Interrupt(self.mode == GuestDescriptorAccess::Mode::Publish);
            return false;
        }
        self.state->writer = std::this_thread::get_id();
        ++self.state->depth;
        self.state->replacement = self.state->replacement || self.mode == GuestDescriptorAccess::Mode::Change || (self.mode == GuestDescriptorAccess::Mode::Close || self.mode == GuestDescriptorAccess::Mode::Publish) || self.mode == GuestDescriptorAccess::Mode::Replace;
    }
    self.held = true;
    return true;
}

void DescriptorAccessDrain_nid_no_patch(void* access, bool closing) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) return;
    std::unique_lock lock(self.state->mutex);
    while (self.state->readers != 0) {
        self.state->Interrupt(closing);
        self.state->changed.wait_for(lock, std::chrono::milliseconds(1));
    }
}

void DescriptorAccessMarkChanged_nid_no_patch(void* access) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) return;
    std::lock_guard lock(self.state->mutex);
    self.state->replacement = true;
}

void DescriptorAccessUnlock_nid_no_patch(void* access) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) { self.held = false; return; }
    {
        std::lock_guard lock(self.state->mutex);
        if (self.mode == GuestDescriptorAccess::Mode::Read) --self.state->readers;
        else if (--self.state->depth == 0) {
            self.state->writer = {};
            if (self.state->replacement && self.state->generation != std::numeric_limits<std::uint64_t>::max()) ++self.state->generation;
            self.state->replacement = false;
        }
        self.held = false;
    }
    self.state->Notify();
}

bool DescriptorAccessReadOrWait_nid_no_patch(void* access) {
    return DescriptorAccessReadOrWaitUntil_nid_no_patch(access, 0);
}

bool DescriptorAccessReadOrWaitUntil_nid_no_patch(void* access, std::int64_t deadlineNanos) {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) { self.held = true; return true; }
    std::unique_lock lock(self.state->mutex);
    if (self.state->CanRead()) {
        ++self.state->readers;
        self.held = true;
        return true;
    }
    std::unique_lock wakeLock(self.state->wakeMutex);
    const auto revision = self.state->revision;
    lock.unlock();
    const auto woken = [&] { return self.wakePending || self.state->revision != revision; };
    if (deadlineNanos == 0) self.state->wakeChanged.wait(wakeLock, woken);
    else self.state->wakeChanged.wait_until(wakeLock,
        std::chrono::steady_clock::time_point(std::chrono::nanoseconds(deadlineNanos)), woken);
    self.wakePending = false;
    return false;
}

void DescriptorAccessWake_nid_no_patch(void* access) noexcept {
    auto& self = *static_cast<GuestDescriptorAccess*>(access);
    if (!self.state) return;
    {
        std::lock_guard lock(self.state->wakeMutex);
        self.wakePending = true;
        ++self.state->revision;
    }
    self.state->wakeChanged.notify_all();
    self.state->changed.notify_all();
}

bool DescriptorVersionUnchanged_nid_no_patch(const void* version) {
    const auto& self = *static_cast<const GuestDescriptorAccess::Version*>(version);
    if (!self.state) return false;
    std::lock_guard lock(self.state->mutex);
    return self.value != std::numeric_limits<std::uint64_t>::max() && self.state->generation == self.value && self.state->closesWaiting == 0;
}

bool DescriptorVersionMatches_nid_no_patch(const void* version) {
    const auto& self = *static_cast<const GuestDescriptorAccess::Version*>(version);
    if (!self.state) return false;
    std::lock_guard lock(self.state->mutex);
    return self.value != std::numeric_limits<std::uint64_t>::max() && self.state->generation == self.value;
}

void DescriptorAccessSnapshot_nid_no_patch(const void* access, void* version) {
    const auto& self = *static_cast<const GuestDescriptorAccess*>(access);
    auto& result = *static_cast<GuestDescriptorAccess::Version*>(version);
    if (!self.state) return;
    std::lock_guard lock(self.state->mutex);
    result.state = self.state;
    result.value = self.state->generation;
}

thread_local GuestDescriptorAccess::Operation* GuestDescriptorAccess::Operation::current = nullptr;

void DescriptorOperationInitialize_nid_no_patch(void* operation, void* access) {
    auto& self = *static_cast<GuestDescriptorAccess::Operation*>(operation);
    self.state = static_cast<GuestDescriptorAccess*>(access)->state;
    self.previous = GuestDescriptorAccess::Operation::current;
    if (self.state) {
        std::lock_guard lock(self.state->mutex);
        self.state->operations.push_back(&self);
        self.interrupted.store(self.state->closesWaiting != 0 || (self.retireOnReplace && self.state->replacementsWaiting != 0));
    }
    GuestDescriptorAccess::Operation::current = &self;
}

void DescriptorOperationDestroy_nid_no_patch(void* operation) {
    auto& self = *static_cast<GuestDescriptorAccess::Operation*>(operation);
    GuestDescriptorAccess::Operation::current = self.previous;
    if (self.state) {
        std::lock_guard lock(self.state->mutex);
        std::erase(self.state->operations, &self);
    }
}

bool DescriptorOperationInterrupted_nid_no_patch() {
    const auto* current = GuestDescriptorAccess::Operation::current;
    return current && current->Interrupted();
}

void GuestDescriptorAccess::Operation::Interrupt() noexcept {
    interrupted.store(true);
    for (auto* registration = wake; registration; registration = registration->previous)
        registration->interrupt(registration->argument);
}

void GuestDescriptorAccess::Operation::Refresh() noexcept {
    refresh.store(true);
    for (auto* registration = wake; registration; registration = registration->previous)
        registration->interrupt(registration->argument);
}

void DescriptorWakeInitialize_nid_no_patch(void* registration) {
    auto& self = *static_cast<GuestDescriptorAccess::Operation::WakeRegistration*>(registration);
    self.operation = GuestDescriptorAccess::Operation::current;
    if (!self.operation || !self.operation->state) { self.operation = nullptr; return; }
    std::lock_guard lock(self.operation->state->mutex);
    self.previous = self.operation->wake;
    self.operation->wake = &self;
}

void DescriptorWakeDestroy_nid_no_patch(void* registration) {
    auto& self = *static_cast<GuestDescriptorAccess::Operation::WakeRegistration*>(registration);
    if (!self.operation) return;
    std::lock_guard lock(self.operation->state->mutex);
    self.operation->wake = self.previous;
}

namespace {
std::atomic<void (*)(int, int)> streamCloseHook{nullptr};
}

void FileStreamSetCloseHookForTest_nid_no_patch(void (*hook)(int, int)) {
    streamCloseHook.store(hook);
}

bool FileStreamCloseHookActive_nid_no_patch() {
    return streamCloseHook.load() != nullptr;
}

void FileStreamCloseEventForTest_nid_no_patch(int descriptor, int event) {
    if (const auto hook = streamCloseHook.load()) hook(descriptor, event);
}
