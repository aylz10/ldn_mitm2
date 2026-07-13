#include "nifm_manager.hpp"
#include "debug.hpp"

namespace ams::mitm::ldn {

    os::SdkMutex NifmSessionManager::g_mutex;
    bool NifmSessionManager::g_initialized = false;
    int NifmSessionManager::g_refcount = 0;

    Result NifmSessionManager::Acquire() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount == 0) {
            Result rc = nifmInitialize(NifmServiceType_Admin);
            if (R_FAILED(rc)) {
                LogFormat("NifmSessionManager: nifmInitialize failed: %x", rc);
                return rc;
            }
            g_initialized = true;
            LogFormat("NifmSessionManager: session acquired");
        }

        g_refcount++;
        return 0;
    }

    void NifmSessionManager::Release() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount <= 0) {
            LogFormat("NifmSessionManager: unbalanced Release (refcount %d)", g_refcount);
            return;
        }

        g_refcount--;

        if (g_refcount == 0 && g_initialized) {
            nifmExit();
            g_initialized = false;
            LogFormat("NifmSessionManager: session released");
        }
    }

}
