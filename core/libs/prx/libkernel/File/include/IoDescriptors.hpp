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
        std::optional<GuestDescriptorAccess::Operation> operation;
        std::optional<ThreadCancel::IoWait> wake;
        explicit Entry(int descriptor)
            : descriptor(descriptor), access(descriptor, GuestDescriptorAccess::Mode::Read, std::defer_lock), version(access.Snapshot()) {}
    };
    std::vector<std::unique_ptr<Entry>> entries;

    void Release() {
        for (auto entry = entries.rbegin(); entry != entries.rend(); ++entry) {
            (*entry)->wake.reset();
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
        return found != entries.end() && (((*found)->operation && (*found)->operation->Interrupted()) || !(*found)->version.Unchanged());
    }

    bool Acquire(ThreadCancel::IoWait::Interrupt interrupt, void* argument) {
        for (;;) {
            if (ThreadCancel::IoInterrupted()) return false;
            Entry* blocked = nullptr;
            for (auto& entry : entries) {
                if (!entry->version.Unchanged()) { Release(); return false; }
                if (!entry->access.TryLock()) { blocked = entry.get(); break; }
                entry->held = true;
                if (!entry->version.Unchanged()) { Release(); return false; }
            }
            if (!blocked) break;
            Release();
            ThreadCancel::IoWait wait([](void* opaque) noexcept {
                static_cast<GuestDescriptorAccess*>(opaque)->Wake();
            }, &blocked->access);
            while (!ThreadCancel::IoInterrupted()) {
                if (blocked->access.ReadOrWait()) {
                    blocked->access.Unlock();
                    break;
                }
            }
        }
        for (auto& entry : entries) {
            entry->operation.emplace(entry->access, true);
            entry->wake.emplace(interrupt, argument);
        }
        return !ThreadCancel::IoInterrupted();
    }
};

}
