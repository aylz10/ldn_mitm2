#pragma once
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* nifm:a allows only two sessions system-wide; hold one only while needed. */
    class NifmSessionManager {
        private:
            static os::SdkMutex g_mutex;
            static bool g_initialized;
            static int g_refcount;
        public:
            static Result Acquire();
            static void Release();
    };

    class ScopedNifmSession {
        private:
            Result rc;
        public:
            ScopedNifmSession() : rc(NifmSessionManager::Acquire()) {}
            ~ScopedNifmSession() {
                if (R_SUCCEEDED(rc)) {
                    NifmSessionManager::Release();
                }
            }
            Result GetResult() const { return rc; }
    };

}
