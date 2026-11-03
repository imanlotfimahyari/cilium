/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Actual endpoint entrypoints and Cilium policy/CT, with a synthetic underlay
 * and direct endpoint-delivery fixture. No Cilium agent or CNI is started.
 */
#define VTEP_HANDOFF_CILIUM_CORE 1
#include "socket_handoff.c"
