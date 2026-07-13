#include "lan_discovery.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include "ipinfo.hpp"

namespace ams::mitm::ldn {

    static const int ModuleID = 0xFD;
    static const int LdnModuleId = 0xCB;
    /* nn::ldn ConnectFailed (2203-0064). */
    static const Result ResultConnectFailed = MAKERESULT(0xCB, 64);

    const char *LANDiscovery::FakeSsid = "12345678123456781234567812345678";
    const LANDiscovery::LanEventFunc LANDiscovery::EmptyFunc = [](){};


    int LanStation::onRead() {
        if (!this->socket) {
            LogFormat("Nullptr %d\n", this->nodeId);
            return -1;
        }
        return this->socket->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
			AMS_UNUSED(reply);
            if (type == LANPacketType::Connect) {
                LogFormat("on connect");
                NodeInfo *info = (decltype(info))data;
                if (size != sizeof(*info)) {
                    LogFormat("NodeInfo size is wrong");
                    return -1;
                }
                std::scoped_lock lock(this->discovery->dataMutex);
                *this->nodeInfo = *info;
                this->status = NodeStatus::Connected;

                this->discovery->updateNodes();
            } else {
                LogFormat("unexpecting type %d", static_cast<int>(type));
            }
            return 0;
        });
    }

    void LanStation::onClose() {
        LogFormat("LanStation::onClose %d", this->nodeId);
        this->reset();
        this->discovery->updateNodes();
    }

    LDUdpSocket::LDUdpSocket(int fd, LANDiscovery *discovery)
        :   UdpLanSocketBase(fd, discovery->getListenPort()),
            discovery(discovery) {
        /* ... */
    }

    int LDUdpSocket::onRead() {
        LogFormat("LDUdpSocket::onRead");
        return this->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
            switch (type) {
                case LANPacketType::Scan: {
                    if (this->discovery->getState() == CommState::AccessPointCreated) {
                        std::scoped_lock lock(this->discovery->dataMutex);
                        reply(LANPacketType::ScanResp, &this->discovery->networkInfo, sizeof(NetworkInfo));
                    }
                    break;
                }
                case LANPacketType::ScanResp: {
                    LogFormat("ScanResp");
                    NetworkInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        break;
                    }
                    std::scoped_lock lock(this->discovery->dataMutex);
                    /* Drop our own advertisement echoed back by a relay. */
                    if (this->selfIp != 0 && info->ldn.nodes[0].ipv4Address == this->selfIp) {
                        LogFormat("ScanResp: ignoring our own network (echoed back by relay)");
                        break;
                    }
                    this->scanResults.insert({info->common.bssid, *info});
                    break;
                }
                default: {
                    LogFormat("LDUdpSocket::onRead unhandle type %d", static_cast<int>(type));
                    break;
                }
            }
            return 0;
        });
    }

    void LDUdpSocket::onClose() {
        discovery->disconnect_reason = DisconnectReason::SignalLost;
        discovery->setState(CommState::Error);
    };

    int LDTcpSocket::onRead() {
        LogFormat("LDTcpSocket::onRead");
        const auto state = this->discovery->getState();
        if (state == CommState::Station || state == CommState::StationConnected) {
            return this->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
				AMS_UNUSED(reply);
                if (type == LANPacketType::SyncNetwork) {
                    LogFormat("SyncNetwork");
                    NetworkInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        return -1;
                    }

                    this->discovery->onSyncNetwork(info);
                } else {
                    LogFormat("LDTcpSocket::onRead unhandle type %d", static_cast<int>(type));
                    return -1;
                }

                return 0;
            });
        } else if (state == CommState::AccessPointCreated) {
            struct sockaddr_in addr;
            socklen_t addrlen = sizeof(addr);
            int new_fd = accept(this->getFd(), (struct sockaddr *)&addr, &addrlen);
            if (new_fd < 0)
            {
                LogFormat("accept failed");
                return -1;
            }
            this->discovery->onConnect(new_fd);
            return 0;
        } else {
            LogFormat("LDTcpSocket::onRead wrong state %d", static_cast<int>(state));
            return -1;
        }
    }

    void LDTcpSocket::onClose() {
        LogFormat("LDTcpSocket::onClose");
        this->close();
        this->discovery->onDisconnectFromHost();
    }

    u32 LDUdpSocket::getBroadcast() {
        u32 address, netmask, gateway, primary_dns, secondary_dns;
        Result rc = nifmGetCurrentIpConfigInfo(&address, &netmask, &gateway, &primary_dns, &secondary_dns);
        address = ntohl(address);
        netmask = ntohl(netmask);
        if (R_FAILED(rc)) {
            LogFormat("Broadcast failed to get ip");
            return 0xFFFFFFFF;
        }
        u32 ret = address | ~netmask;
        return ret;
    }

    void LANDiscovery::onSyncNetwork(NetworkInfo *info) {
        std::scoped_lock lock(this->dataMutex);
        this->networkInfo = *info;
        if (this->state == CommState::Station) {
            this->setState(CommState::StationConnected);
        }
        this->onNetworkInfoChanged();
    }

    void LANDiscovery::onConnect(int new_fd) {
        LogFormat("Accepted %d", new_fd);
        if (this->stationCount() >= StationCountMax) {
            LogFormat("Close new_fd. stations are full");
            close(new_fd);
            return;
        }

        /* Accepted sockets don't reliably inherit options from the listener. */
        this->setSocketOpts(new_fd, true);

        bool found = false;
        for (auto &i : this->stations) {
            if (i.getStatus() == NodeStatus::Disconnected) {
                i.link(new_fd);
                found = true;
                break;
            }
        }

        if (!found) {
            LogFormat("Close new_fd. no free station found");
            close(new_fd);
        }
    }

    void LANDiscovery::onDisconnectFromHost() {
        LogFormat("onDisconnectFromHost state: %d", static_cast<int>(this->state));
        if (this->state == CommState::StationConnected) {
            this->disconnect_reason = DisconnectReason::SignalLost;
            this->setState(CommState::Station);
        }
    }

    void LANDiscovery::onNetworkInfoChanged() {
        if (this->isNodeStateChanged()) {
            this->lanEvent();
        }
        return;
    }

    Result LANDiscovery::setAdvertiseData(const u8 *data, uint16_t size) {
        if (size > AdvertiseDataSizeMax) {
            return MAKERESULT(ModuleID, 10);
        }

        std::scoped_lock lock(this->dataMutex);
        if (size > 0 && data != nullptr) {
            std::memcpy(this->networkInfo.ldn.advertiseData, data, size);
        } else {
            LogFormat("LANDiscovery::setAdvertiseData data %p size %lu", data, size);
        }
        this->networkInfo.ldn.advertiseDataSize = size;

        this->updateNodes();

        return 0;
    }

    Result LANDiscovery::initNetworkInfo() {
        Result rc = getFakeMac(&this->networkInfo.common.bssid);
        if (R_FAILED(rc)) {
            return rc;
        }
        this->networkInfo.common.channel = 6;
        this->networkInfo.common.linkLevel = 3;
        this->networkInfo.common.networkType = 2;
        this->networkInfo.common.ssid = FakeSsid;

        auto nodes = this->networkInfo.ldn.nodes;
        for (int i = 0; i < NodeCountMax; i++) {
            nodes[i].nodeId = i;
            nodes[i].isConnected = 0;
        }

        return 0;
    }

    Result LANDiscovery::getFakeMac(MacAddress *mac) {
        mac->raw[0] = 0x02;
        mac->raw[1] = 0x00;

        u32 ip;
        Result rc = nifmGetCurrentIpAddress(&ip);
        if (R_SUCCEEDED(rc)) {
            ip = ntohl(ip);
            memcpy(mac->raw + 2, &ip, sizeof(ip));
        }

        return rc;
    }

    Result LANDiscovery::setSocketOpts(int fd, bool isTcp) {
        int rc;

        if (!isTcp) {
            int b = 1;
            rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &b, sizeof(b));
            if (rc != 0) {
                return MAKERESULT(ModuleID, 4);
            }
        }
        {
            int yes = 1;
            rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
            if (rc != 0) {
                // return MAKERESULT(ModuleID, 5);
                LogFormat("SO_REUSEADDR failed");
            }
        }
        if (isTcp) {
            int nodelay = 1;
            rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            if (rc != 0) {
                LogFormat("TCP_NODELAY failed");
            }
            struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
            rc = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (rc != 0) {
                LogFormat("SO_SNDTIMEO failed");
            }
        }

        return 0;
    }

    Result LANDiscovery::initTcp(bool listening) {
        int fd;
        Result rc;
        struct sockaddr_in addr;
        std::scoped_lock lock(this->pollMutex);

        if (this->tcp) {
            this->tcp->close();
        }
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return MAKERESULT(ModuleID, 6);
        }
        auto tcpSocket = std::make_unique<LDTcpSocket>(fd, this);

        rc = setSocketOpts(fd, true);
        if (R_FAILED(rc)) {
            return rc;
        }
        if (listening) {
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(listenPort);
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                return MAKERESULT(ModuleID, 7);
            }
            if (listen(fd, 10) != 0) {
                return MAKERESULT(ModuleID, 8);
            }
        }

        this->tcp = std::move(tcpSocket);

        return 0;
    }

    Result LANDiscovery::initUdp(bool listening) {
        int fd;
        Result rc;
        struct sockaddr_in addr;
        std::scoped_lock lock(this->pollMutex);

        if (this->udp) {
            this->udp->close();
        }
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return MAKERESULT(ModuleID, 1);
        }
        auto udpSocket = std::make_unique<LDUdpSocket>(fd, this);

        rc = setSocketOpts(fd, false);
        if (R_FAILED(rc)) {
            return rc;
        }
        if (listening) {
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(listenPort);
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                return MAKERESULT(ModuleID, 2);
            }
        }

        this->udp = std::move(udpSocket);

        return 0;
    }

    void LANDiscovery::initNodeStateChange() {
        for (auto &i : this->nodeChanges) {
            i.stateChange = NodeStateChange_None;
        }
        for (auto &i : this->nodeLastStates) {
            i = 0;
        }
    }

    bool LANDiscovery::isNodeStateChanged() {
        bool changed = false;
        const auto &nodes = this->networkInfo.ldn.nodes;
        for (int i = 0; i < NodeCountMax; i++) {
            if (nodes[i].isConnected != this->nodeLastStates[i]) {
                if (nodes[i].isConnected) {
                    this->nodeChanges[i].stateChange |= NodeStateChange_Connect;
                } else {
                    this->nodeChanges[i].stateChange |= NodeStateChange_Disconnect;
                }
                this->nodeLastStates[i] = nodes[i].isConnected;
                changed = true;
            }
        }
        return changed;
    }

    void LANDiscovery::Worker(void* args) {
        LANDiscovery* self = (LANDiscovery*)args;

        self->worker();
    }

    Result LANDiscovery::scan(NetworkInfo *pOutNetwork, u16 *count, ScanFilter filter) {
        if (!this->initialized || !this->udp) {
            *count = 0;
            return MAKERESULT(ModuleID, 20);
        }

        {
            std::scoped_lock lock(this->dataMutex);
            this->udp->scanResults.clear();
            u32 myIp = 0;
            if (R_SUCCEEDED(nifmGetCurrentIpAddress(&myIp))) {
                this->udp->selfIp = ntohl(myIp);
            } else {
                this->udp->selfIp = 0;
            }
        }

        /* Rebroadcast every 300ms; stop once results are stable for two checks. */
        size_t lastCount = 0;
        int stable = 0;
        for (int j = 0; j < 10; j++) {
            if (j % 3 == 0) {
                int len = this->udp->sendBroadcast(LANPacketType::Scan);
                if (len < 0 && j == 0) {
                    return MAKERESULT(ModuleID, 20);
                }
            }
            svcSleepThread(100000000L); // 100ms

            std::scoped_lock lock(this->dataMutex);
            const size_t cur = this->udp->scanResults.size();
            if (cur > 0 && cur == lastCount) {
                if (++stable >= 2) {
                    break;
                }
            } else {
                stable = 0;
            }
            lastCount = cur;
        }

        std::scoped_lock lock(this->dataMutex);
        LogFormat("scan filter flag %x comm %lx scene %d type %u session %lx.%lx ssid(%d) %.32s",
            filter.flag,
            filter.networkId.intentId.localCommunicationId, filter.networkId.intentId.sceneId,
            filter.networkType,
            filter.networkId.sessionId.high, filter.networkId.sessionId.low,
            filter.ssid.length, filter.ssid.raw);
        int i = 0;
        for (auto& item : this->udp->scanResults) {
            if (i >= *count) {
                break;
            }
            auto &info = item.second;

            bool copy = true;
            // filter
            if (filter.flag & ScanFilterFlag_LocalCommunicationId) {
                copy &= filter.networkId.intentId.localCommunicationId == info.networkId.intentId.localCommunicationId;
            }
            if (filter.flag & ScanFilterFlag_SessionId) {
                copy &= filter.networkId.sessionId == info.networkId.sessionId;
            }
            if (filter.flag & ScanFilterFlag_NetworkType) {
                copy &= filter.networkType == info.common.networkType;
            }
            if (filter.flag & ScanFilterFlag_Ssid) {
                copy &= filter.ssid == info.common.ssid;
            }
            if (filter.flag & ScanFilterFlag_SceneId) {
                copy &= filter.networkId.intentId.sceneId == info.networkId.intentId.sceneId;
            }

            LogFormat("scan cand comm %lx scene %d type %u session %lx.%lx ssid(%d) %.32s -> %d",
                info.networkId.intentId.localCommunicationId, info.networkId.intentId.sceneId,
                info.common.networkType,
                info.networkId.sessionId.high, info.networkId.sessionId.low,
                info.common.ssid.length, info.common.ssid.raw,
                static_cast<int>(copy));

            if (copy) {
                pOutNetwork[i++] = info;
            }
        }
        *count = i;

        return 0;
    }

    void LANDiscovery::resetStations() {
        for (auto &i : this->stations) {
            i.reset();
        }
    }

    int LANDiscovery::stationCount() {
        int count = 0;

        for (auto const &i : this->stations) {
            if (i.getStatus() != NodeStatus::Disconnected) {
                count++;
            }
        }

        return count;
    }

    void LANDiscovery::updateNodes() {
        std::scoped_lock lock(this->dataMutex);
        int count = 0;
        for (auto &i : this->stations) {
            bool connected = i.getStatus() == NodeStatus::Connected;
            if (connected) {
                count++;
            }
            i.overrideInfo();
        }
        this->networkInfo.ldn.nodeCount = count + 1;

        for (auto &i : stations) {
            if (i.getStatus() == NodeStatus::Connected) {
                int ret = i.sendPacket(LANPacketType::SyncNetwork, &this->networkInfo, sizeof(this->networkInfo));
                if (ret < 0) {
                    LogFormat("Failed to sendTcp");
                }
            }
        }

        this->onNetworkInfoChanged();
    }

    int LANDiscovery::loopPoll() {
        int rc;
        if (!initialized) {
            return 0;
        }

        std::scoped_lock lock(this->pollMutex);
        int nfds = 2 + StationCountMax;
        Pollable *fds[nfds];
        fds[0] = this->udp.get();
        fds[1] = this->tcp.get();
        for (int i = 0; i < StationCountMax; i++) {
            fds[2 + i] = this->stations.data() + i;
        }
        rc = Pollable::Poll(fds, nfds);

        return rc;
    }

    LANDiscovery::~LANDiscovery() {
        LogFormat("~LANDiscovery");
        if (this->initialized) {
            LogFormat("finalize not called");
            Result rc = this->finalize();
            LogFormat("finalize: %d", rc);
        }
    }

    void LANDiscovery::worker() {
        this->stop = false;
        while (!this->stop) {

            int rc = loopPoll();
            if (rc < 0) {
                break;
            }
            /* Brief unlocked window so IPC threads can grab pollMutex. */
            svcSleepThread(1000000L); // 1ms
        }
        LogFormat("Worker exit");
    }

    Result LANDiscovery::getNetworkInfo(NetworkInfo *pOutNetwork) {
        Result rc = 0;

        if (this->state == CommState::AccessPointCreated || this->state == CommState::StationConnected) {
            std::scoped_lock lock(this->dataMutex);
            std::memcpy(pOutNetwork, &networkInfo, sizeof(networkInfo));
        } else {
            rc = MAKERESULT(LdnModuleId, 32);
        }

        return rc;
    }

    Result LANDiscovery::getNetworkInfo(NetworkInfo *pOutNetwork, NodeLatestUpdate *pOutUpdates, int bufferCount) {
        Result rc = 0;

        if (bufferCount < 0 || bufferCount > NodeCountMax) {
            return MAKERESULT(ModuleID, 50);
        }

        if (this->state == CommState::AccessPointCreated || this->state == CommState::StationConnected) {
            std::scoped_lock lock(this->dataMutex);
            std::memcpy(pOutNetwork, &networkInfo, sizeof(networkInfo));

            char str[10] = {0};
            for (int i = 0; i < bufferCount; i++) {
                pOutUpdates[i].stateChange = nodeChanges[i].stateChange;
                nodeChanges[i].stateChange = NodeStateChange_None;
                str[i] = '0' + pOutUpdates[i].stateChange;
            }
            LogFormat("getNetworkInfo updates %s", str);
        } else {
            rc = MAKERESULT(LdnModuleId, 32);
        }

        return rc;
    }

    Result LANDiscovery::getNodeInfo(NodeInfo *node, const UserConfig *userConfig, u16 localCommunicationVersion) {
        u32 ipAddress;
        Result rc = nifmGetCurrentIpAddress(&ipAddress);
        if (R_FAILED(rc))
        {
            return rc;
        }
        ipAddress = ntohl(ipAddress);
        rc = getFakeMac(&node->macAddress);
        if (R_FAILED(rc)) {
            return rc;
        }

        node->isConnected = 1;
        strcpy(node->userName, userConfig->userName);
        node->localCommunicationVersion = localCommunicationVersion;
        node->ipv4Address = ipAddress;

        return 0;
    }

    Result LANDiscovery::createNetwork(const SecurityConfig *securityConfig, const UserConfig *userConfig, const NetworkConfig *networkConfig) {
        return this->createNetworkImpl(securityConfig, nullptr, userConfig, networkConfig);
    }

    Result LANDiscovery::createNetworkPrivate(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig) {
        return this->createNetworkImpl(securityConfig, securityParameter, userConfig, networkConfig);
    }

    Result LANDiscovery::createNetworkImpl(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig) {
        LogFormat("SecurityConfig");
        LogHex(securityConfig->passphrase, securityConfig->passphraseSize);
        Result rc = 0;

        if (this->state != CommState::AccessPoint) {
            return MAKERESULT(LdnModuleId, 32);
        }

        rc = this->initTcp(true);
        if (R_FAILED(rc)) {
            return rc;
        }

        /* initTcp takes pollMutex, so it must run before dataMutex is taken. */
        std::scoped_lock lock(this->dataMutex);
        rc = this->initNetworkInfo();
        if (R_FAILED(rc)) {
            return rc;
        }
        this->networkInfo.ldn.nodeCountMax = networkConfig->nodeCountMax;
        this->networkInfo.ldn.securityMode = securityConfig->securityMode;

        if (networkConfig->channel == 0) {
            this->networkInfo.common.channel = 6;
        } else {
            this->networkInfo.common.channel = networkConfig->channel;
        }

        if (securityParameter != nullptr) {
            /* The session id comes from the link code. */
            std::memcpy(&this->networkInfo.networkId.sessionId, securityParameter->sessionId, sizeof(SessionId));
            std::memcpy(this->networkInfo.ldn.unkRandom, securityParameter->unkRandom, sizeof(this->networkInfo.ldn.unkRandom));
        } else {
            ams::os::GenerateRandomBytes(&this->networkInfo.networkId.sessionId, sizeof(SessionId));
        }
        this->networkInfo.networkId.intentId = networkConfig->intentId;
        LogFormat("createNetwork comm %lx scene %d session %lx.%lx",
            this->networkInfo.networkId.intentId.localCommunicationId,
            this->networkInfo.networkId.intentId.sceneId,
            this->networkInfo.networkId.sessionId.high, this->networkInfo.networkId.sessionId.low);

        NodeInfo *node0 = &this->networkInfo.ldn.nodes[0];
        rc = this->getNodeInfo(node0, userConfig, networkConfig->localCommunicationVersion);
        if (R_FAILED(rc)) {
            return rc;
        }

        this->setState(CommState::AccessPointCreated);

        this->initNodeStateChange();
        node0->isConnected = 1;
        this->updateNodes();

        return rc;
    }

    Result LANDiscovery::destroyNetwork() {
        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::AccessPoint);

        return 0;
    }

    Result LANDiscovery::disconnect() {
        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
        }
        this->setState(CommState::Station);

        return 0;
    }

    Result LANDiscovery::openAccessPoint() {
        this->disconnect_reason = DisconnectReason::None;
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }

        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::AccessPoint);

        return 0;
    }

    Result LANDiscovery::closeAccessPoint() {
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }

        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::Initialized);

        return 0;
    }

    Result LANDiscovery::openStation() {
        this->disconnect_reason = DisconnectReason::None;
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }

        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::Station);

        return 0;
    }

    Result LANDiscovery::closeStation() {
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }

        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::Initialized);

        return 0;
    }

    Result LANDiscovery::connect(const NetworkInfo *networkInfo, UserConfig *userConfig, u16 localCommunicationVersion) {
        if (networkInfo->ldn.nodeCount == 0) {
            return MAKERESULT(ModuleID, 30);
        }

        u32 hostIp = networkInfo->ldn.nodes[0].ipv4Address;

        u32 myIp;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&myIp))) {
            myIp = ntohl(myIp);
            if (hostIp == myIp) {
                LogFormat("connect: host IP %x equals our own; refusing self-connect", hostIp);
                return ResultConnectFailed;
            }
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(hostIp);
        addr.sin_port = htons(listenPort);
        LogFormat("connect hostIp %x", hostIp);

        Result rc = this->initTcp(false);
        if (R_FAILED(rc)) {
            return rc;
        }

        const int fd = this->tcp->getFd();
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        int ret = ::connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret != 0) {
            if (flags < 0 || errno != EINPROGRESS) {
                LogFormat("connect failed");
                return ResultConnectFailed;
            }
            struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
            ret = poll(&pfd, 1, 5000);
            if (ret <= 0) {
                LogFormat("connect timeout");
                return ResultConnectFailed;
            }
            int err = 0;
            socklen_t errlen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0 || err != 0) {
                LogFormat("connect failed. SO_ERROR %d", err);
                return ResultConnectFailed;
            }
        }
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags);
        }

        NodeInfo myNode = {0};
        rc = this->getNodeInfo(&myNode, userConfig, localCommunicationVersion);
        if (R_FAILED(rc)) {
            return rc;
        }
        ret = this->tcp->sendPacket(LANPacketType::Connect, &myNode, sizeof(myNode));
        if (ret < 0) {
            LogFormat("sendPacket failed");
            return ResultConnectFailed;
        }
        {
            std::scoped_lock lock(this->dataMutex);
            this->initNodeStateChange();
        }

        bool synced = false;
        for (int j = 0; j < 300; j++) {
            if (this->state == CommState::StationConnected) {
                synced = true;
                break;
            }
            svcSleepThread(10000000L); // 10ms
        }

        if (!synced) {
            LogFormat("connect: no SyncNetwork from host, aborting join");
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            return ResultConnectFailed;
        }

        return 0;
    }

    Result LANDiscovery::connectPrivate(const SecurityParameterData *securityParameter, const UserConfig *userConfig, u16 localCommunicationVersion, const NetworkConfig *networkConfig) {
        AMS_UNUSED(networkConfig);

        /* ConnectPrivate gives no NetworkInfo: scan for the link code's session id. */
        ScanFilter filter = {};
        std::memcpy(&filter.networkId.sessionId, securityParameter->sessionId, sizeof(SessionId));
        filter.flag = ScanFilterFlag_SessionId;

        constexpr u16 ResultCountMax = 8;
        auto results = std::make_unique<NetworkInfo[]>(ResultCountMax);

        u32 myIp = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&myIp))) {
            myIp = ntohl(myIp);
        } else {
            myIp = 0;
        }

        for (int attempt = 0; attempt < 3; attempt++) {
            u16 count = ResultCountMax;
            Result rc = this->scan(results.get(), &count, filter);
            if (R_FAILED(rc)) {
                continue;
            }
            for (u16 j = 0; j < count; j++) {
                if (myIp != 0 && results[j].ldn.nodes[0].ipv4Address == myIp) {
                    LogFormat("connectPrivate: skipping self result %x", myIp);
                    continue;
                }
                LogFormat("connectPrivate: found session on attempt %d idx %d", attempt, j);
                UserConfig config = *userConfig;
                return this->connect(&results[j], &config, localCommunicationVersion);
            }
        }

        LogFormat("connectPrivate: no network with matching session id");
        return ResultConnectFailed;
    }

    Result LANDiscovery::finalize() {
        Result rc = 0;

        if (this->initialized) {
            this->stop = true;
            os::WaitThread(&this->workerThread);
            os::DestroyThread(&this->workerThread);
            this->udp.reset();
            this->tcp.reset();
            this->resetStations();
            this->initialized = false;

            rc = nifmRequestCancel(&request);
            if (R_FAILED(rc))
            {
                LogFormat("final nifmRequestCancel failed: %x", rc);
            }
            /* Close frees the request session; Cancel alone leaks it. */
            nifmRequestClose(&request);

            NifmNetworkProfileData networkProfile;
            rc = nifmGetCurrentNetworkProfile(&networkProfile);
            if (R_FAILED(rc))
            {
                LogFormat("final nifmGetCurrentProfile failed: %x", rc);
            } else if (networkProfile.ip_setting_data.mtu != originalMtu) {
                networkProfile.ip_setting_data.mtu = originalMtu;
                rc = nifmSetNetworkProfile(&networkProfile, &networkProfile.uuid);
                if (R_FAILED(rc)) {
                    LogFormat("final nifmSetNetworkProfile failed: %x", rc);
                }
            }
        }

        this->setState(CommState::None);

        return rc;
    }

    Result LANDiscovery::initialize(LanEventFunc lanEvent, bool listening) {
        if (this->initialized)
        {
            return 0;
        }

        NifmNetworkProfileData networkProfile;
        Result rc = nifmGetCurrentNetworkProfile(&networkProfile);
        if (R_FAILED(rc))
        {
            LogFormat("nifmGetCurrentNetworkProfile failed: %x", rc);
            return rc;
        }

        originalMtu = networkProfile.ip_setting_data.mtu;
        /* A low profile MTU breaks pia games (2618-0006). */
        int desiredMtu = originalMtu;
        if (desiredMtu == 0 || desiredMtu > 1500) {
            desiredMtu = 1500;
        }

        bool mtuChanged = false;
        if (desiredMtu != originalMtu) {
            networkProfile.ip_setting_data.mtu = desiredMtu;
            rc = nifmSetNetworkProfile(&networkProfile, &networkProfile.uuid);
            if (R_FAILED(rc)) {
                LogFormat("nifmSetNetworkProfile failed: %x", rc);
                return rc;
            }
            mtuChanged = true;
        }

        auto restoreMtu = [&]() {
            if (!mtuChanged) {
                return;
            }
            NifmNetworkProfileData p;
            if (R_SUCCEEDED(nifmGetCurrentNetworkProfile(&p))) {
                p.ip_setting_data.mtu = originalMtu;
                nifmSetNetworkProfile(&p, &p.uuid);
            }
        };

        rc = nifmCreateRequest(&request, true);
        if (R_FAILED(rc))
        {
            LogFormat("nifmCreateRequest failed: %x", rc);
            restoreMtu();
            return rc;
        }

        rc = nifmSetLocalNetworkMode(&request, true);
        if (R_FAILED(rc)) {
            LogFormat("nifmSetLocalNetworkMode failed %x", rc);
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return rc;
        }

        rc = nifmRequestSubmitAndWait(&request);
        if (R_FAILED(rc))
        {
            LogFormat("nifmRequestSubmitAndWait failed: %x", rc);
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return rc;
        }

        for (auto &i : stations) {
            i.discovery = this;
            i.nodeInfo = &this->networkInfo.ldn.nodes[i.nodeId];
            i.reset();
        }

        this->lanEvent = lanEvent;
        rc = this->initUdp(listening);
        if (R_FAILED(rc)) {
            LogFormat("initUdp %x", rc);
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return rc;
        }

        rc = os::CreateThread(&this->workerThread, &Worker, this, reinterpret_cast<void *>(util::AlignUp(reinterpret_cast<uintptr_t>(stack.get()), os::ThreadStackAlignment)), StackSize, 0x15, 2);
        if (R_FAILED(rc)) {
            LogFormat("LANDiscovery Failed to threadCreate: %x", rc);
            this->udp.reset();
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return 0xF601;
        }

        os::StartThread(&this->workerThread);
        this->setState(CommState::Initialized);

        this->initialized = true;
        return 0;
    }
}
