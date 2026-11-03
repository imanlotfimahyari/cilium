/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Actual endpoint policy/CT consumes the shared production TIME-WAIT proof.
 * The independent tracing object only produces proofs; no synthetic route
 * hook is attached by this fixture.
 */
#define ENABLE_VTEP_RETURN_TIMEWAIT_AFFINITY 1
#include "socket_core.c"
