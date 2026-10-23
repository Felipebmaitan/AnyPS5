# libSceJobManager technical debt

### Functional

- [Compute sequences](../../../core/libs/prx/libSceJobManager/Export.cpp) encode commands when runnable instead of ahead with native rewind packets. The bounded command area throws when exhausted; the original traps. Maximum register lists and markers can exhaust it before the logical dispatch limit. Compute dispatch on a CPU sequence and shutdown with outstanding compute work throw.
- [Scheduling state and nodes](../../../core/libs/prx/libSceJobManager/Export.cpp) remain on the host heap. Blocks below 0x2d8 bytes, factory priorities above one, use of destroyed sequences and shutdown from a worker throw. Host mutexes and condition variables replace native atomic queues and semaphores; spin intervals deliberately use unscaled host TSC. Calls concurrent with shutdown are unverified.
- [Profiler events](../../../core/libs/prx/libSceJobManager/Export.cpp) are not forwarded. Resource-creation failures throw after cleanup, where the original does not check every return. The fallback Wait deliberately allocates no pool node; native Wait can stall on global pool exhaustion. Vtable order was checked, but no calling title or PS5 timing equivalence has been tested.
