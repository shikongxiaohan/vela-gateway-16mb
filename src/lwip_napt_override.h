/*
 * lwip_napt_override.h
 *
 * NAPT build marker for the Vela Gateway firmware.
 *
 * This header is included early by main.cpp (guarded by
 * VELA_DISABLE_LWIP_OVERRIDE) and exposes a single no-op marker function that
 * records, at the call site, that the lwIP NAPT build options below are the
 * ones the forwarding code assumes.
 *
 * NAPT forwarding is provided end-to-end by configuration plus runtime calls,
 * not by any patched lwIP internals:
 *
 *   - sdkconfig: CONFIG_LWIP_IP_FORWARD=y
 *                CONFIG_LWIP_IPV4_NAPT=y
 *                CONFIG_LWIP_L2_TO_L3_COPY=y
 *                (the espidf+arduino low-memory env recompiles lwIP so these
 *                 actually take effect; in a prebuilt-library env they do not)
 *
 *   - runtime:   explicit ip_napt_enable(softap_netif, 1) plus route repair,
 *                see setupWatchNetworkProxy() / repairDefaultRoute() in
 *                main.cpp
 *
 * The marker therefore has no required side effect. Keeping it as an inline
 * no-op preserves the call site for source compatibility. If lwIP ever needs a
 * real internal patch, that implementation can replace this stub without
 * touching main.cpp.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C++" {
#endif

static inline void vela_lwip_napt_override_marker(void) {
    /* no-op marker: NAPT is enabled via sdkconfig + ip_napt_enable() */
}

#ifdef __cplusplus
}
#endif
