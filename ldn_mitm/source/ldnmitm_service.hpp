#pragma once
#include <switch.h>
#include <stratosphere.hpp>
#include <cstring>
#include <atomic>
#include "ldn_icommunication.hpp"
#include "ldn_client_process_monitor.hpp"
#include "ldnmitm_config.hpp"
#include "debug.hpp"
#include "interfaces/iservice.hpp"

namespace ams::mitm::ldn {

    class LdnMitMService : public sf::MitmServiceImplBase {
        private:
            using RedirectOnlyLocationResolverFactory = sf::ObjectFactory<sf::StdAllocationPolicy<std::allocator>>;
        public:
            LdnMitMService(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c);
            
            static bool ShouldMitm(const sm::MitmProcessInfo &client_info) {
                /* Always mitm non-applications so the overlay can reach the config service. */
                const bool is_app = ncm::IsApplicationId(client_info.program_id);
                const bool mitm = !is_app || LdnConfig::getEnabled();
                LogFormat("should_mitm pid: %" PRIu64 " tid: %" PRIx64 " app %d -> %d",
                    client_info.process_id, client_info.program_id,
                    static_cast<int>(is_app), static_cast<int>(mitm));
                return mitm;
            }
        // protected:
        public:
            /* Overridden commands. */
            Result CreateUserLocalCommunicationService(sf::Out<sf::SharedPointer<ICommunicationInterface>> out);
            Result CreateClientProcessMonitor(sf::Out<sf::SharedPointer<IClientProcessMonitorInterface>> out);
            Result CreateLdnMitmConfigService(sf::Out<sf::SharedPointer<ILdnConfig>> out);
    };
    static_assert(ams::mitm::ldn::IsILdnMitMService<LdnMitMService>);

}