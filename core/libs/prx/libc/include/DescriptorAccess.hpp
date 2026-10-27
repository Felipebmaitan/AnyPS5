#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_DESCRIPTORACCESS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_DESCRIPTORACCESS_HPP

#include <memory>
#include <mutex>
#include <cstdint>

class GuestDescriptorAccess {
    struct State;
public:
    class Version {
    public:
        bool Unchanged() const;
    private:
        friend class GuestDescriptorAccess;
        Version(std::shared_ptr<State> state, std::uint64_t value);
        std::shared_ptr<State> state;
        std::uint64_t value;
    };
    enum class Mode { Read, Change, Update };
    GuestDescriptorAccess(int descriptor, Mode mode);
    GuestDescriptorAccess(int descriptor, Mode mode, std::defer_lock_t);
    ~GuestDescriptorAccess();
    GuestDescriptorAccess(const GuestDescriptorAccess&) = delete;
    GuestDescriptorAccess& operator=(const GuestDescriptorAccess&) = delete;
    void Lock();
    bool TryLock();
    void Unlock();
    bool ReadOrWait();
    void Wake() noexcept;
    Version Snapshot() const;
    static void LockTogether(GuestDescriptorAccess& first, GuestDescriptorAccess& second);

private:
    static std::shared_ptr<State> Get(int descriptor);
    std::shared_ptr<State> state;
    Mode mode;
    bool held = false;
};

#endif
