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

union sysfs_devattr_value {
	unsigned long	ulong;
	void		*ptr;
};

enum {
	SYSFS_DEVATTR_IFINDEX		= 0,
	SYSFS_DEVATTR_TYPE		= 1,
	SYSFS_DEVATTR_FLAGS		= 2,
	SYSFS_DEVATTR_ADDR_LEN		= 3,
	SYSFS_DEVATTR_ADDRESS		= 4,
	SYSFS_DEVATTR_BROADCAST		= 5,
	SYSFS_DEVATTR_NUM
};

struct sysfs_devattr_values
{
	char *ifname;
	union sysfs_devattr_value	value[SYSFS_DEVATTR_NUM];
};

struct device;

#ifdef USE_SYSFS
extern void sysfs_devattr_values_init(struct sysfs_devattr_values *v, int do_free);
extern int find_device_by_sysfs(struct device *device);
extern int set_device_broadcast_sysfs(struct sysfs_devattr_values *v, unsigned char *ba, size_t balen);
#else
static inline void sysfs_devattr_values_init(struct sysfs_devattr_values *v, int do_free) { return; }
static inline int find_device_by_sysfs(struct device *device) { return -1; }
static inline int set_device_broadcast_sysfs(struct sysfs_devattr_values *v, unsigned char *ba, size_t balen) { return -1; }
#endif
