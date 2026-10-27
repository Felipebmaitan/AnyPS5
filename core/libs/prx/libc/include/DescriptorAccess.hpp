#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_DESCRIPTORACCESS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_DESCRIPTORACCESS_HPP

#include <memory>
#include <mutex>

class GuestDescriptorAccess {
public:
    enum class Mode { Read, Change };
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
    static void LockTogether(GuestDescriptorAccess& first, GuestDescriptorAccess& second);

private:
    struct State;
    static std::shared_ptr<State> Get(int descriptor);
    std::shared_ptr<State> state;
    Mode mode;
    bool held = false;
};

#endif
