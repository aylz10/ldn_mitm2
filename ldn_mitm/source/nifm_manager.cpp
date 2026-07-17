#include "nifm_manager.hpp"
#include "debug.hpp"

namespace ams::mitm::ldn {

    os::SdkMutex NifmSessionManager::g_mutex;
    int NifmSessionManager::g_refcount = 0;

    Result NifmSessionManager::Acquire() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount == 0) {
            Result rc = nifmInitialize(NifmServiceType_Admin);
            if (R_FAILED(rc)) {
                LogFormat("NifmSessionManager: nifmInitialize failed: %x", rc);
                return rc;
            }
            LogFormat("NifmSessionManager: session acquired");
        }

        g_refcount++;
        R_SUCCEED();
    }

    void NifmSessionManager::Release() {
        std::scoped_lock lk(g_mutex);

        if (g_refcount <= 0) {
            LogFormat("NifmSessionManager: unbalanced Release (refcount %d)", g_refcount);
            return;
        }

        g_refcount--;

        if (g_refcount == 0) {
            nifmExit();
            LogFormat("NifmSessionManager: session released");
        }
    }

}
