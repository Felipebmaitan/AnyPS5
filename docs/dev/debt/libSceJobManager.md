# libSceJobManager technical debt

### Functional

- [Compute sequences](../../../core/libs/prx/libSceJobManager/Export.cpp) use explicit release packets instead of native rewind and completion-packet patching across GPU barriers. The bounded command area throws when exhausted; the original traps. Maximum register lists and markers can exhaust it before the logical dispatch limit. Compute dispatch on a CPU sequence throws.
- [Scheduling](../../../core/libs/prx/libSceJobManager/Export.cpp) uses host mutexes and condition variables instead of native atomic queues and semaphores; spin intervals deliberately use unscaled host TSC. Blocks below 0x2d8 bytes, factory priorities above one, use of destroyed sequences and shutdown from a worker throw. New calls concurrent with shutdown are unverified.
- [Pool allocation](../../../core/libs/prx/libSceJobManager/Export.cpp) reuses freed nodes in a different order; profiler dispatch IDs can differ from native allocation. The fallback Wait deliberately allocates no pool node; native Wait can stall on global pool exhaustion. Resource-creation failures throw after cleanup, where the original does not check every return. Vtable order was checked, but no calling title or PS5 timing equivalence has been tested.
