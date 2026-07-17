#pragma once

#include <switch.h>
#include <stratosphere.hpp>
#include "interfaces/iconfig.hpp"

namespace ams::mitm::ldn {

    class LdnConfig {
        public:
            static bool getEnabled() {
                return LdnEnabled;
            }
            /* Broadcast->unicast fan-out in the bsd:u mitm. */
            static bool getBroadcastRelay() {
                return BroadcastRelay;
            }
            static void setBroadcastRelay(bool v) {
                BroadcastRelay = v;
            }
        protected:
            static std::atomic_bool LdnEnabled;
            static std::atomic_bool BroadcastRelay;
        public:

            Result GetVersion(sf::Out<LdnMitmVersion> version);
            Result GetLogging(sf::Out<u32> enabled);
            Result SetLogging(u32 enabled);
            Result GetEnabled(sf::Out<u32> enabled);
            Result SetEnabled(u32 enabled);
            Result GetBroadcastRelay(sf::Out<u32> enabled);
            Result SetBroadcastRelay(u32 enabled);
            Result GetInternetRelay(sf::Out<u32> enabled);
            Result SetInternetRelay(u32 enabled);
            Result GetRelayServerCount(sf::Out<u32> count);
            Result GetRelayServerName(u32 index, sf::Out<RelayServerName> name);
            Result GetSelectedRelayServer(sf::Out<u32> index);
            Result SetSelectedRelayServer(u32 index);
    };
    static_assert(ams::mitm::ldn::IsILdnConfig<LdnConfig>);

}
