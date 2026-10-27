#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_GUESTSTACKS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_GUESTSTACKS_HPP

#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstddef>
#include <cstdint>

namespace GuestStacks {

struct Bounds {
    std::uintptr_t low = 0;
    std::uintptr_t high = 0;
    bool Contains(std::uintptr_t address) const { return address >= low && address < high; }
};

extern "C" {

void GuestStackRegister_nid_no_patch(const void* pointer, std::size_t bytes);
Bounds GuestStackBounds_nid_no_patch(std::uintptr_t stackPointer);
void APS5_VABI GuestStackSwitch_nid_no_patch(std::uintptr_t stackPointer);

}

}

#endif
