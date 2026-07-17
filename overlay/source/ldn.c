#include "ldn.h"
#include <string.h>

Result ldnMitmGetConfig(LdnMitmConfigService *out) {
    Handle handle;
    Result rc = svcConnectToNamedPort(&handle, "ldnmitm");
    if (R_SUCCEEDED(rc)) {
        serviceCreate(&out->s, handle);
    }
    return rc;
}

Result ldnMitmGetConfigFromService(Service* s, LdnMitmConfigService *out) {
    return serviceDispatch(s, 65000,
        .out_num_objects = 1,
        .out_objects = &out->s
    );
}

Result ldnMitmGetLogging(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65002, *enabled);
}

Result ldnMitmSetLogging(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65003, enabled);
}

Result ldnMitmGetEnabled(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65004, *enabled);
}

Result ldnMitmSetEnabled(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65005, enabled);
}

Result ldnMitmGetBroadcastRelay(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65006, *enabled);
}

Result ldnMitmSetBroadcastRelay(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65007, enabled);
}

Result ldnMitmGetInternetRelay(LdnMitmConfigService *s, u32 *enabled) {
    return serviceDispatchOut(&s->s, 65008, *enabled);
}

Result ldnMitmSetInternetRelay(LdnMitmConfigService *s, u32 enabled) {
    return serviceDispatchIn(&s->s, 65009, enabled);
}

Result ldnMitmGetRelayServerCount(LdnMitmConfigService *s, u32 *count) {
    return serviceDispatchOut(&s->s, 65010, *count);
}

Result ldnMitmGetRelayServerName(LdnMitmConfigService *s, u32 index, char *name) {
    char name_s[32];
    Result rc = serviceDispatchInOut(&s->s, 65011, index, name_s);
    if (R_SUCCEEDED(rc)) {
        memcpy(name, name_s, sizeof(name_s));
        name[31] = '\0';
    }
    return rc;
}

Result ldnMitmGetSelectedRelayServer(LdnMitmConfigService *s, u32 *index) {
    return serviceDispatchOut(&s->s, 65012, *index);
}

Result ldnMitmSetSelectedRelayServer(LdnMitmConfigService *s, u32 index) {
    return serviceDispatchIn(&s->s, 65013, index);
}

Result ldnMitmGetVersion(LdnMitmConfigService *s, char *version) {
    char version_s[32];
    Result rc = serviceDispatchOut(&s->s, 65001, version_s);
    if (R_SUCCEEDED(rc)) {
        strcpy(version, version_s);
    }
    return rc;
}

Result ldnMitmSaveLogToFile(LdnMitmConfigService *s) {
    return serviceDispatch(&s->s, 65000);
}