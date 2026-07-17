#include <cstring>
#include "ldnmitm_config.hpp"
#include "relay_client.hpp"
#include "debug.hpp"

namespace ams::mitm::ldn {
    std::atomic_bool LdnConfig::LdnEnabled = true;
    std::atomic_bool LdnConfig::BroadcastRelay = true;

    Result LdnConfig::GetVersion(sf::Out<LdnMitmVersion> version) {
        std::strcpy(version.GetPointer()->raw, GITDESCVER);
        
        R_SUCCEED();
    }
    Result LdnConfig::GetLogging(sf::Out<u32> enabled) {
        return ::GetLogging(enabled.GetPointer());
    }
    Result LdnConfig::SetLogging(u32 enabled) {
        return ::SetLogging(enabled);
    }
    Result LdnConfig::GetEnabled(sf::Out<u32> enabled) {
        enabled.SetValue(LdnEnabled);
        
        R_SUCCEED();
    }
    Result LdnConfig::SetEnabled(u32 enabled) {
        LdnEnabled = enabled;

        R_SUCCEED();
    }
    Result LdnConfig::GetBroadcastRelay(sf::Out<u32> enabled) {
        enabled.SetValue(BroadcastRelay);

        R_SUCCEED();
    }
    Result LdnConfig::SetBroadcastRelay(u32 enabled) {
        BroadcastRelay = enabled;
        relay::PersistSettings();

        R_SUCCEED();
    }

    Result LdnConfig::GetInternetRelay(sf::Out<u32> enabled) {
        enabled.SetValue(relay::GetRelayEnabled() ? 1 : 0);
        R_SUCCEED();
    }
    Result LdnConfig::SetInternetRelay(u32 enabled) {
        relay::SetRelayEnabled(enabled != 0);
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayServerCount(sf::Out<u32> count) {
        count.SetValue(static_cast<u32>(relay::ServerCount()));
        R_SUCCEED();
    }
    Result LdnConfig::GetRelayServerName(u32 index, sf::Out<RelayServerName> name) {
        RelayServerName out = {};
        std::strncpy(out.name, relay::ServerName(static_cast<int>(index)), sizeof(out.name) - 1);
        name.SetValue(out);
        R_SUCCEED();
    }
    Result LdnConfig::GetSelectedRelayServer(sf::Out<u32> index) {
        index.SetValue(static_cast<u32>(relay::SelectedServer()));
        R_SUCCEED();
    }
    Result LdnConfig::SetSelectedRelayServer(u32 index) {
        relay::SelectServer(static_cast<int>(index));
        R_SUCCEED();
    }
}
