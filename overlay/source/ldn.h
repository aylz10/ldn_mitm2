#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Service s;
} LdnMitmConfigService;

Result ldnMitmSaveLogToFile(LdnMitmConfigService *s);
Result ldnMitmGetVersion(LdnMitmConfigService *s, char *version);
Result ldnMitmGetLogging(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetLogging(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetEnabled(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetEnabled(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetBroadcastRelay(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetBroadcastRelay(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetInternetRelay(LdnMitmConfigService *s, u32 *enabled);
Result ldnMitmSetInternetRelay(LdnMitmConfigService *s, u32 enabled);
Result ldnMitmGetRelayServerCount(LdnMitmConfigService *s, u32 *count);
Result ldnMitmGetRelayServerName(LdnMitmConfigService *s, u32 index, char *name);
Result ldnMitmGetSelectedRelayServer(LdnMitmConfigService *s, u32 *index);
Result ldnMitmSetSelectedRelayServer(LdnMitmConfigService *s, u32 index);
Result ldnMitmGetConfig(LdnMitmConfigService *out);
Result ldnMitmGetConfigFromService(Service* s, LdnMitmConfigService *out);

#ifdef __cplusplus
}
#endif
