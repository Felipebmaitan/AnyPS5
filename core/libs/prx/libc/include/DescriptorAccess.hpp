#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_DESCRIPTORACCESS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_DESCRIPTORACCESS_HPP

#include <memory>
#include <mutex>
#include <cstdint>
#include <atomic>

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
    enum class Mode { Read, Change, Update, Close };
    class Operation {
    public:
        explicit Operation(GuestDescriptorAccess& access);
        ~Operation();
        Operation(const Operation&) = delete;
        Operation& operator=(const Operation&) = delete;
        bool Interrupted() const { return interrupted.load(); }
        static bool CurrentInterrupted();
        class WakeRegistration {
        public:
            WakeRegistration(void (*interrupt)(void*) noexcept, void* argument);
            ~WakeRegistration();
            WakeRegistration(const WakeRegistration&) = delete;
            WakeRegistration& operator=(const WakeRegistration&) = delete;
        private:
            friend class Operation;
            WakeRegistration* previous = nullptr;
            Operation* operation;
            void (*interrupt)(void*) noexcept;
            void* argument;
        };
    private:
        friend struct State;
        static thread_local Operation* current;
        std::shared_ptr<State> state;
        Operation* previous;
        WakeRegistration* wake = nullptr;
        std::atomic<bool> interrupted{false};
        void Interrupt() noexcept;
    };
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
