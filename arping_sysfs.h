/*
 * arping_sysfs.h
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Author:
 *	YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

struct device;

#ifdef USE_SYSFS
extern int find_device_by_sysfs(struct device *device);
extern int set_device_broadcast_sysfs(struct device *device, unsigned char *ba, size_t balen);
#else
static inline int find_device_by_sysfs(struct device *device) { return -1; }
static inline int set_device_broadcast_sysfs(struct device *device, unsigned char *ba, size_t balen) { return -1; }
#endif
