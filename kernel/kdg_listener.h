/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KDG_LISTENER_H
#define _KDG_LISTENER_H

#include <linux/types.h>

/* Prepare starts loopback UDP/TCP listeners without claiming port 53. */
int kdg_listener_init_state(void);
int kdg_listener_prepare(void);
void kdg_listener_stop(void);
bool kdg_listener_ready(void);

#endif /* _KDG_LISTENER_H */
