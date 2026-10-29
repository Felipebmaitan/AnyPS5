#pragma once

#include "prx/libkernel/Pthread/include/Cancel.hpp"
#include <algorithm>
#include <memory>
#include <optional>
#include <vector>

namespace File {

class IoDescriptors {
    struct Entry {
        int descriptor;
        GuestDescriptorAccess access;
        GuestDescriptorAccess::Version version;
        bool held = false;
        bool retired = false;
        std::optional<GuestDescriptorAccess::Operation> operation;
        std::optional<ThreadCancel::IoWait> wake;
        explicit Entry(int descriptor)
            : descriptor(descriptor), access(descriptor, GuestDescriptorAccess::Mode::Read, std::defer_lock), version(access.Snapshot()) {}
    };
    std::vector<std::unique_ptr<Entry>> entries;

    void Release() {
        for (auto entry = entries.rbegin(); entry != entries.rend(); ++entry) {
            (*entry)->wake.reset();
            if ((*entry)->operation && (*entry)->operation->Interrupted()) (*entry)->retired = true;
            (*entry)->operation.reset();
            if ((*entry)->held) {
                (*entry)->access.Unlock();
                (*entry)->held = false;
            }
        }
    }

public:
    explicit IoDescriptors(std::vector<int> descriptors) {
        std::sort(descriptors.begin(), descriptors.end());
        descriptors.erase(std::unique(descriptors.begin(), descriptors.end()), descriptors.end());
        for (const int descriptor : descriptors)
            if (descriptor >= 0) entries.push_back(std::make_unique<Entry>(descriptor));
    }
    ~IoDescriptors() { Release(); }
    IoDescriptors(const IoDescriptors&) = delete;
    IoDescriptors& operator=(const IoDescriptors&) = delete;

    bool Retired(int descriptor) const {
        const auto found = std::find_if(entries.begin(), entries.end(), [descriptor](const auto& entry) {
            return entry->descriptor == descriptor;
        });
        return found != entries.end() && ((*found)->retired || ((*found)->operation && (*found)->operation->Interrupted()) || !(*found)->version.Unchanged());
    }

    bool Available(int descriptor) const {
        const auto found = std::find_if(entries.begin(), entries.end(), [descriptor](const auto& entry) {
            return entry->descriptor == descriptor;
        });
        return found != entries.end() && (*found)->held;
    }

    bool Pending() const {
        for (const auto& entry : entries)
            if (!entry->held && !Retired(entry->descriptor)) return true;
        return false;
    }

    bool Acquire(ThreadCancel::IoWait::Interrupt interrupt, void* argument) {
        Release();
        for (auto& entry : entries) {
            if (ThreadCancel::IoRequestInterrupted()) return false;
            if (Retired(entry->descriptor) || !entry->access.TryLock()) continue;
            entry->held = true;
            if (Retired(entry->descriptor)) continue;
            entry->operation.emplace(entry->access, true);
            entry->wake.emplace(interrupt, argument);
        }
        return !ThreadCancel::IoRequestInterrupted();
    }

    void Wait(std::optional<std::chrono::steady_clock::time_point> deadline) {
        Entry* blocked = nullptr;
        for (auto& entry : entries) {
            if (!entry->held && !Retired(entry->descriptor)) { blocked = entry.get(); break; }
        }
        Release();
        if (!blocked) return;
        ThreadCancel::IoWait wait([](void* opaque) noexcept {
            static_cast<GuestDescriptorAccess*>(opaque)->Wake();
        }, &blocked->access);
        if (ThreadCancel::IoRequestInterrupted()) return;
        auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(1);
        if (deadline) until = std::min(until, *deadline);
        if (blocked->access.ReadOrWaitUntil(until)) blocked->access.Unlock();
    }
};

}
