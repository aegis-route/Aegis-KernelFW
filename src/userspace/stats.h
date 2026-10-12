#ifndef __STATS_H__
#define __STATS_H__

#include <stdint.h>
#include "../../include/aegis_types.h"

/* Query and display static snapshot of all packet counters */
int stats_display(void);

/* Real-time live monitor dashboard (refreshes every interval_sec) */
int stats_monitor(int interval_sec);

/* Reset all statistical counters to zero */
int stats_reset(void);

#endif /* __STATS_H__ */
