#pragma once
#include <stratosphere.hpp>
#include "debug.hpp"
#include <memory>
#include <thread>
#include <array>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <stdint.h>
#include <unistd.h>
#include <cstring>
#include "ldn_types.hpp"
#include "lan_protocol.hpp"
#include "relay_client.hpp"

namespace ams::mitm::ldn {
    const size_t StackSize = 0x4000;
    enum class NodeStatus : u8 {
        Disconnected,
        Connect,
        Connected,
    };
    enum class DisconnectReason {
        None,
        DisconnectedByUser,
        DisconnectedBySystem,
        DestroyedByUser,
        DestroyedBySystem,
        Rejected,
        SignalLost
    };

    class LANDiscovery;

    /* RelayHeartbeat/RelayBye payload; ipv4 is the sender, host order. */
    struct RelayHeartbeatPayload {
        MacAddress bssid;
        u8 _pad[2];
        u32 ipv4;
    };

    /* Relay Connect: NodeInfo then target bssid; a bare NodeInfo is also accepted. */
    constexpr size_t RelayConnectPayloadSize = sizeof(NodeInfo) + sizeof(MacAddress);

    class LanStation : public Pollable {
        protected:
            friend class LANDiscovery;
            friend class RelayLanSocket;
            NodeInfo *nodeInfo;
            NodeStatus status;
            std::unique_ptr<TcpLanSocketBase> socket;
            int nodeId;
            LANDiscovery *discovery;
        public:
            /* Relay stations only. Guarded by discovery->dataMutex. */
            os::Tick lastSeen = os::Tick(0);
        public:
            LanStation(int nodeId, LANDiscovery *discovery)
                : nodeInfo(nullptr),
                status(NodeStatus::Disconnected),
                nodeId(nodeId),
                discovery(discovery)
            {}
            NodeStatus getStatus() const {
                return this->status;
            }
            void reset() {
                this->socket.reset();
                this->status = NodeStatus::Disconnected;
            };
            void link(int fd) {
                this->socket = std::make_unique<TcpLanSocketBase>(fd);
                this->status = NodeStatus::Connect;
            };
            int getFd() override {
                if (!this->socket) {
                    return -1;
                }
                return this->socket->getFd();
            };
            int onRead() override;
            void onClose() override;
            int sendPacket(LANPacketType type, const void *data, size_t size) {
                if (!this->socket) {
                    return -1;
                }
                return this->socket->sendPacket(type, data, size);
            };
            void overrideInfo() {
                bool connected = this->getStatus() == NodeStatus::Connected;
                this->nodeInfo->nodeId = this->nodeId;
                if (connected) {
                    this->nodeInfo->isConnected = 1;
                } else {
                    this->nodeInfo->isConnected = 0;
                }
            }
    };

    class LDUdpSocket : public UdpLanSocketBase, public Pollable {
        protected:
            struct MacHash {
                std::size_t operator() (const MacAddress &t) const {
                    return *reinterpret_cast<const u32*>(t.raw + 2);
                }
            };
            virtual u32 getBroadcast() override;
            LANDiscovery *discovery;
        public:
            std::unordered_map<MacAddress, NetworkInfo, MacHash> scanResults;
        public:
            LDUdpSocket(int fd, LANDiscovery *discovery);
            int getFd() override {
                return UdpLanSocketBase::getFd();
            }
            int onRead() override;
            void onClose() override;
    };

    class LDTcpSocket : public TcpLanSocketBase, public Pollable {
        protected:
            LANDiscovery *discovery;
            bool hostClosed = false;
        public:
            LDTcpSocket(int fd, LANDiscovery *discovery) : TcpLanSocketBase(fd), discovery(discovery) {};
            int getFd() override {
                return TcpLanSocketBase::getFd();
            }
            int onRead() override;
            void onClose() override;
    };

    class RelayLanSocket : public UdpLanSocketBase, public Pollable {
        protected:
            relay::RelayTransport transport;
            LANDiscovery *discovery;
            u32 lastSrc = 0;
            virtual u32 getBroadcast() override { return 0x0A0DFFFFu; } /* 10.13.255.255 */
            virtual ssize_t recvfrom(void *buf, size_t len, struct sockaddr_in *addr) override;
            virtual int sendto(const void *buf, size_t len, struct sockaddr_in *addr) override;
        public:
            RelayLanSocket(LANDiscovery *discovery) : UdpLanSocketBase(-1, 11452), discovery(discovery) {}
            Result open() { return this->transport.Open(); }
            int getFd() override { return this->transport.GetFd(); }
            int onRead() override;
            void onClose() override;
            void keepalive() { this->transport.SendKeepalive(); }
            void ping() { this->transport.SendPing(); }
            void sendScope(u32 token) { this->transport.SendScope(token); }
            bool pathDead() const { return this->transport.PathDead(); }
            Result reopen() { return this->transport.Reopen(); }
    };

    class LANDiscovery {
        public:
            static const int DefaultPort = 11452;
            /* Relay re-announce interval; must stay under the server's 60s idle timeout. */
            static constexpr s64 RelayBeaconIntervalMs = 5000;
            static constexpr s64 RelayPeerTimeoutMs = 30000;
            static constexpr s64 RelayAdvertiseMinIntervalMs = 2000;
            static constexpr s64 RelayReconnectMinIntervalMs = 15000;
            static const char *FakeSsid;
            typedef std::function<int(LANPacketType, const void *, size_t)> ReplyFunc;
            typedef std::function<void()> LanEventFunc;
            static const LanEventFunc EmptyFunc;
            DisconnectReason disconnect_reason;
        protected:
            friend class LDUdpSocket;
            friend class LDTcpSocket;
            friend class LanStation;
            friend class RelayLanSocket;
            os::Mutex pollMutex;
            // Recursive: updateNodes() runs both with and without it held.
            // Lock order: pollMutex may be held when taking dataMutex, never the reverse.
            os::Mutex dataMutex;
            std::unique_ptr<LDUdpSocket> udp;
            std::unique_ptr<LDTcpSocket> tcp;
            std::unique_ptr<RelayLanSocket> relay;
            std::array<LanStation, StationCountMax> stations;
            std::array<NodeLatestUpdate, NodeCountMax> nodeChanges;
            std::array<u8, NodeCountMax> nodeLastStates;
            static void Worker(void* args);
            NifmRequest request;
            int originalMtu;
            std::atomic_bool stop;
            bool initialized;
            NetworkInfo networkInfo;
            /* Guarded by dataMutex (through lastRelayAdvertise). */
            u32 scanSelfIp = 0;
            MacAddress joinBssid{};
            bool joinActive = false;
            u16 relaySyncSeq = 0;
            bool relaySyncSeqValid = false;
            os::Tick hostLastSeen = os::Tick(0);
            bool relayJoined = false;
            u32 relayJoinedIp = 0;
            u32 joinAwaitSelfIp = 0;
            os::Tick lastRelayAdvertise = os::Tick(0);
            /* Worker thread only. */
            os::Tick lastRelayReconnect = os::Tick(0);
            std::atomic<bool> initRelay{false};
            bool initListening = true;
            std::atomic<bool> needsReinit{false};
            Result refreshNetworkSession();
            u16 listenPort;
            os::ThreadType workerThread;
            CommState state;
            void worker();
            int loopPoll();
            /* relaySeq 0 skips the staleness check (non-relay sync). */
            void onSyncNetwork(NetworkInfo *info, u16 relaySeq = 0);
            void onConnect(int new_fd);
            void onRelayConnect(const NodeInfo *info, const MacAddress *targetBssid);
            void addScanResult(const NetworkInfo *info);
            /* Call with dataMutex held. */
            LanStation *findRelayStation(u32 ipv4);
            void sendRelayBye();
            void sendRelayScope();
            void onDisconnectFromHost(DisconnectReason reason);
            void onNetworkInfoChanged();
            void clearJoinState();

            void updateNodes();
            /* Call with dataMutex held. */
            void publishSessionRegistry();
            void resetStations();
            void closeTcpAndStations();
            Result getFakeMac(MacAddress *mac);
            Result getNodeInfo(NodeInfo *node, const UserConfig *userConfig, u16 localCommunicationVersion);
            LanEventFunc lanEvent;
            std::unique_ptr<u8[]> stack;
        public:
            Result initialize(LanEventFunc lanEvent = EmptyFunc, bool listening = true);
            Result finalize();
            Result initNetworkInfo();
            Result scan(NetworkInfo *networkInfo, u16 *count, ScanFilter filter);
            Result setAdvertiseData(const u8 *data, uint16_t size);
            Result createNetwork(const SecurityConfig *securityConfig, const UserConfig *userConfig, const NetworkConfig *networkConfig);
            Result createNetworkPrivate(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig);
            Result destroyNetwork();
            Result connect(const NetworkInfo *networkInfo, const UserConfig *userConfig, u16 localCommunicationVersion);
            Result connectPrivate(const SecurityParameterData *securityParameter, const UserConfig *userConfig, u16 localCommunicationVersion, const NetworkConfig *networkConfig);
            Result disconnect();
            Result getNetworkInfo(NetworkInfo *pOutNetwork);
            Result getNetworkInfo(NetworkInfo *pOutNetwork, NodeLatestUpdate *pOutUpdates, int bufferCount);
            Result openAccessPoint();
            Result closeAccessPoint();
            Result openStation();
            Result closeStation();
        public:
            LANDiscovery(u16 port = DefaultPort) :
                disconnect_reason(DisconnectReason::None),
                pollMutex(false),
                dataMutex(true),
                stations({{{1, this}, {2, this}, {3, this}, {4, this}, {5, this}, {6, this}, {7, this}}}),
                stop(false), initialized(false),
                networkInfo({}), listenPort(port),
                state(CommState::None)
            {
                this->stack = std::make_unique<u8[]>(os::ThreadStackAlignment + StackSize);
                LogFormat("LANDiscovery");
            };
            ~LANDiscovery();
            u16 getListenPort() const {
                return this->listenPort;
            }
            CommState getState() const {
                return this->state;
            };
            void setState(CommState v) {
                this->state = v;
                this->lanEvent();
            };
            int stationCount();
        protected:
            Result createNetworkImpl(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig);
            Result setSocketOpts(int fd, bool isTcp);
            Result initTcp(bool listening);
            Result initUdp(bool listening);
            void initNodeStateChange();
            bool isNodeStateChanged();
    };
}
