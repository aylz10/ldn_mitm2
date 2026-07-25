#include "ldn_icommunication.hpp"
#include "nifm_manager.hpp"
#include <arpa/inet.h>

namespace ams::mitm::ldn {
    static_assert(sizeof(NetworkInfo) == 0x480, "sizeof(NetworkInfo) should be 0x480");
    static_assert(sizeof(ConnectNetworkData) == 0x7C, "sizeof(ConnectNetworkData) should be 0x7C");
    static_assert(sizeof(ScanFilter) == 0x60, "sizeof(ScanFilter) should be 0x60");
    static_assert(sizeof(SecurityParameterData) == 0x20, "sizeof(SecurityParameterData) should be 0x20");
    static_assert(sizeof(CreateNetworkPrivateConfig) == 0xB8, "sizeof(CreateNetworkPrivateConfig) should be 0xB8");
    static_assert(offsetof(CreateNetworkPrivateConfig, networkConfig) == 0x98, "CreateNetworkPrivateConfig::networkConfig should be at 0x98");
    static_assert(sizeof(ConnectPrivateParam) == 0xC0, "sizeof(ConnectPrivateParam) should be 0xC0");
    static_assert(offsetof(ConnectPrivateParam, networkConfig) == 0xA0, "ConnectPrivateParam::networkConfig should be at 0xA0");

    // https://reswitched.github.io/SwIPC/ifaces.html#nn::ldn::detail::IUserLocalCommunicationService

    Result ICommunicationService::Initialize(const sf::ClientProcessId &client_process_id) {
        LogFormat("ICommunicationService::Initialize pid: %" PRIu64, client_process_id);

        if (this->state_event == nullptr) {
            // ClearMode, inter_process
            this->state_event = new os::SystemEvent(::ams::os::EventClearMode_AutoClear, true);
        }

        R_TRY(lanDiscovery.initialize([&](){
            this->onEventFired();
        }));

        return ResultSuccess();
    }

    Result ICommunicationService::InitializeSystem2(u64 unk, const sf::ClientProcessId &client_process_id) {
        LogFormat("ICommunicationService::InitializeSystem2 unk: %" PRIu64, unk);
        this->error_state = unk;
        return this->Initialize(client_process_id);
    }

    Result ICommunicationService::Finalize() {
        Result rc = lanDiscovery.finalize();
        if (this->state_event) {
            delete this->state_event;
            this->state_event = nullptr;
        }
        return rc;
    }

    Result ICommunicationService::OpenAccessPoint() {
        return this->lanDiscovery.openAccessPoint();
    }

    Result ICommunicationService::CloseAccessPoint() {
        return this->lanDiscovery.closeAccessPoint();
    }

    Result ICommunicationService::DestroyNetwork() {
        return this->lanDiscovery.destroyNetwork();
    }

    Result ICommunicationService::OpenStation() {
        return this->lanDiscovery.openStation();
    }

    Result ICommunicationService::CloseStation() {
        return this->lanDiscovery.closeStation();
    }

    Result ICommunicationService::Disconnect() {
        return this->lanDiscovery.disconnect();
    }

    Result ICommunicationService::CreateNetwork(CreateNetworkConfig data) {
        return this->lanDiscovery.createNetwork(&data.securityConfig, &data.userConfig, &data.networkConfig);;
    }

    Result ICommunicationService::SetAdvertiseData(sf::InAutoSelectBuffer data) {
        return lanDiscovery.setAdvertiseData(data.GetPointer(), data.GetSize());
    }

    Result ICommunicationService::GetState(sf::Out<u32> state) {
        state.SetValue(static_cast<u32>(this->lanDiscovery.getState()));

        if (this->error_state) {
            if (this->lanDiscovery.disconnect_reason != DisconnectReason::None) {
                return MAKERESULT(0x10, static_cast<u32>(this->lanDiscovery.disconnect_reason));
            }
        }

        return 0;
    }

    Result ICommunicationService::GetIpv4Address(sf::Out<u32> address, sf::Out<u32> netmask) {
        /* Callable before Initialize/after Finalize, when no nifm session is held. */
        ScopedNifmSession session;
        if (R_FAILED(session.GetResult())) {
            return session.GetResult();
        }

        u32 gateway, primary_dns, secondary_dns;
        Result rc = nifmGetCurrentIpConfigInfo(address.GetPointer(), netmask.GetPointer(), &gateway, &primary_dns, &secondary_dns);

        address.SetValue(ntohl(address.GetValue()));
        netmask.SetValue(ntohl(netmask.GetValue()));

        LogFormat("get_ipv4_address %x %x", address.GetValue(), netmask.GetValue());

        return rc;
    }

    Result ICommunicationService::GetNetworkInfo(sf::Out<NetworkInfo> buffer) {
        LogFormat("get_network_info %p state: %d", buffer.GetPointer(), static_cast<u32>(this->lanDiscovery.getState()));

        Result rc = lanDiscovery.getNetworkInfo(buffer.GetPointer());

        if (R_SUCCEEDED(rc)) {
            const NetworkInfo *ni = buffer.GetPointer();
            static u8 s_last_count = 0xff;
            static u32 s_last_ips[NodeCountMax] = {};
            bool changed = (ni->ldn.nodeCount != s_last_count);
            for (int i = 0; i < NodeCountMax; i++) {
                if (ni->ldn.nodes[i].ipv4Address != s_last_ips[i]) {
                    changed = true;
                }
            }
            if (changed) {
                s_last_count = ni->ldn.nodeCount;
                for (int i = 0; i < NodeCountMax; i++) {
                    s_last_ips[i] = ni->ldn.nodes[i].ipv4Address;
                }
                LogFormat("diag netinfo: nodeCount %d/%d secMode %d bssid %02x%02x%02x%02x%02x%02x",
                    ni->ldn.nodeCount, ni->ldn.nodeCountMax, ni->ldn.securityMode,
                    ni->common.bssid.raw[0], ni->common.bssid.raw[1], ni->common.bssid.raw[2],
                    ni->common.bssid.raw[3], ni->common.bssid.raw[4], ni->common.bssid.raw[5]);
                for (int i = 0; i < NodeCountMax; i++) {
                    const NodeInfo &n = ni->ldn.nodes[i];
                    if (n.isConnected || n.ipv4Address != 0) {
                        LogFormat("diag netinfo  node[%d] id %d conn %d ip %08x ver %d user '%.10s'",
                            i, n.nodeId, n.isConnected, n.ipv4Address, n.localCommunicationVersion, n.userName);
                    }
                }
            }
        }

        return rc;
    }

    Result ICommunicationService::GetDisconnectReason(sf::Out<u32> reason) {
        auto dr = static_cast<u32>(this->lanDiscovery.disconnect_reason);
        LogFormat("GetDisconnectReason %p state: %d reason: %u", reason.GetPointer(), static_cast<u32>(this->lanDiscovery.getState()), dr);
        reason.SetValue(dr);

        return 0;
    }

    Result ICommunicationService::GetNetworkInfoLatestUpdate(sf::Out<NetworkInfo> buffer, sf::OutArray<NodeLatestUpdate> pUpdates) {
        LogFormat("get_network_info_latest buffer %p", buffer.GetPointer());
        LogFormat("get_network_info_latest pUpdates %p %" PRIu64, pUpdates.GetPointer(), pUpdates.GetSize());

        return lanDiscovery.getNetworkInfo(buffer.GetPointer(), pUpdates.GetPointer(), pUpdates.GetSize());
    }

    Result ICommunicationService::GetSecurityParameter(sf::Out<SecurityParameter> out) {
        Result rc = 0;

        SecurityParameter data;
        NetworkInfo info;
        rc = lanDiscovery.getNetworkInfo(&info);
        if (R_SUCCEEDED(rc)) {
            NetworkInfo2SecurityParameter(&info, &data);
            out.SetValue(data);
        }

        return rc;
    }

    Result ICommunicationService::GetNetworkConfig(sf::Out<NetworkConfig> out) {
        Result rc = 0;

        NetworkConfig data;
        NetworkInfo info;
        rc = lanDiscovery.getNetworkInfo(&info);
        if (R_SUCCEEDED(rc)) {
            NetworkInfo2NetworkConfig(&info, &data);
            out.SetValue(data);
        }

        return rc;
    }

    Result ICommunicationService::AttachStateChangeEvent(sf::Out<sf::CopyHandle> handle) {
        handle.SetValue(this->state_event->GetReadableHandle(), false);
        return ResultSuccess();
    }

    Result ICommunicationService::Scan(sf::Out<u32> outCount, sf::OutAutoSelectArray<NetworkInfo> buffer, u16 channel, ScanFilter filter) {
		AMS_UNUSED(channel);
        Result rc = 0;
        u16 count = buffer.GetSize();

        rc = lanDiscovery.scan(buffer.GetPointer(), &count, filter);
        outCount.SetValue(count);

        LogFormat("scan %d %d", count, rc);

        return rc;
    }

    Result ICommunicationService::Connect(ConnectNetworkData param, const NetworkInfo &data) {
        LogFormat("ICommunicationService::connect");
        LogHex(&data, sizeof(NetworkInfo));
        LogHex(&param, sizeof(param));

        return lanDiscovery.connect(&data, &param.userConfig, param.localCommunicationVersion);
    }

    void ICommunicationService::onEventFired() {
        if (this->state_event) {
            LogFormat("onEventFired signal_event");
            this->state_event->Signal();
        }
    }

    Result ICommunicationService::ScanPrivate(sf::Out<u32> outCount, sf::OutAutoSelectArray<NetworkInfo> buffer, u16 channel, ScanFilter filter) {
        LogFormat("ICommunicationService::ScanPrivate");
        return this->Scan(outCount, buffer, channel, filter);
    }

    Result ICommunicationService::CreateNetworkPrivate(CreateNetworkPrivateConfig data, const sf::InPointerArray<AddressEntry> &entries) {
        AMS_UNUSED(entries);
        LogFormat("ICommunicationService::CreateNetworkPrivate");
        return lanDiscovery.createNetworkPrivate(&data.securityConfig, &data.securityParameter, &data.userConfig, &data.networkConfig);
    }

    Result ICommunicationService::ConnectPrivate(ConnectPrivateParam param) {
        LogFormat("ICommunicationService::ConnectPrivate");
        return lanDiscovery.connectPrivate(&param.securityParameter, &param.userConfig, param.localCommunicationVersion, &param.networkConfig);
    }

    /*nyi*/
    Result ICommunicationService::SetStationAcceptPolicy(u8 policy) {
		AMS_UNUSED(policy);
        return 0;
    }

    Result ICommunicationService::SetWirelessControllerRestriction() {
        return 0;
    }

    Result ICommunicationService::SetProtocol(u32 protocol) {
        LogFormat("SetProtocol %u", protocol);
        return 0;
    }

    Result ICommunicationService::Reject() {
        return 0;
    }

    Result ICommunicationService::AddAcceptFilterEntry() {
        return 0;
    }

    Result ICommunicationService::ClearAcceptFilter() {
        return 0;
    }
}
