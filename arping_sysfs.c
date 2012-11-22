/*
 * arping_sysfs.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Author:
 *	YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */
#include <stdio.h>
#include <sysfs/libsysfs.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <net/if.h>

#include "arping.h"
#include "arping_sysfs.h"

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

static int sysfs_devattr_ulong_dec(char *ptr, struct sysfs_devattr_values *v, unsigned idx);
static int sysfs_devattr_ulong_hex(char *ptr, struct sysfs_devattr_values *v, unsigned idx);
static int sysfs_devattr_macaddr(char *ptr, struct sysfs_devattr_values *v, unsigned idx);

struct sysfs_devattrs {
	const char *name;
	int (*handler)(char *ptr, struct sysfs_devattr_values *v, unsigned int idx);
	int free;
} sysfs_devattrs[SYSFS_DEVATTR_NUM] = {
	[SYSFS_DEVATTR_IFINDEX] = {
		.name		= "ifindex",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_TYPE] = {
		.name		= "type",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_ADDR_LEN] = {
		.name		= "addr_len",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_FLAGS] = {
		.name		= "flags",
		.handler	= sysfs_devattr_ulong_hex,
	},
	[SYSFS_DEVATTR_ADDRESS] = {
		.name		= "address",
		.handler	= sysfs_devattr_macaddr,
		.free		= 1,
	},
	[SYSFS_DEVATTR_BROADCAST] = {
		.name		= "broadcast",
		.handler	= sysfs_devattr_macaddr,
		.free		= 1,
	},
};

static void sysfs_devattr_values_init(struct sysfs_devattr_values *v, int do_free)
{
	int i;
	if (do_free) {
		free(v->ifname);
		for (i = 0; i < SYSFS_DEVATTR_NUM; i++) {
			if (sysfs_devattrs[i].free)
				free(v->value[i].ptr);
		}
	}
	memset(v, 0, sizeof(*v));
}

static int sysfs_devattr_ulong(char *ptr, struct sysfs_devattr_values *v, unsigned int idx,
				     unsigned int base)
{
	unsigned long *p;
	char *ep;

	if (!ptr || !v)
		return -1;

	p = &v->value[idx].ulong;
	*p = strtoul(ptr, &ep, base);
	if ((*ptr && isspace(*ptr & 0xff)) || errno || (*ep != '\0' && *ep != '\n'))
		goto out;

	return 0;
out:
	return -1;
}

static int sysfs_devattr_ulong_dec(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	int rc = sysfs_devattr_ulong(ptr, v, idx, 10);
	return rc;
}

static int sysfs_devattr_ulong_hex(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	int rc = sysfs_devattr_ulong(ptr, v, idx, 16);
	return rc;
}

static int sysfs_devattr_macaddr(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	unsigned char *m;
	int i;
	unsigned int addrlen;

	if (!ptr || !v)
		return -1;

	addrlen = v->value[SYSFS_DEVATTR_ADDR_LEN].ulong;
	m = malloc(addrlen);

	for (i = 0; i < addrlen; i++) {
		if (i && *(ptr + i * 3 - 1) != ':')
			goto out;
		if (sscanf(ptr + i * 3, "%02hhx", &m[i]) != 1)
			goto out;
	}

	v->value[idx].ptr = m;
	return 0;
out:
	free(m);
	return -1;
}

int find_device_by_sysfs(struct device *device)
{
	struct sysfs_class *cls_net;
	struct dlist *dev_list;
	struct sysfs_class_device *dev;
	struct sysfs_attribute *dev_attr;
	struct sysfs_devattr_values sysfs_devattr_values;

	if (!device)
		return -1;
	if (!device->sysfs) {
		device->sysfs = malloc(sizeof(*device->sysfs));
		sysfs_devattr_values_init(device->sysfs, 0);
	}

	cls_net = sysfs_open_class("net");
	if (!cls_net) {
		perror("sysfs_open_class");
		goto out;
	}

	dev_list = sysfs_get_class_devices(cls_net);
	if (!dev_list) {
		perror("sysfs_get_class_devices");
		goto out;
	}

	sysfs_devattr_values_init(&sysfs_devattr_values, 0);

	dlist_for_each_data(dev_list, dev, struct sysfs_class_device) {
		int i;
		int rc = -1;

		if (device->name && strcmp(dev->name, device->name))
			goto do_next;

		sysfs_devattr_values_init(&sysfs_devattr_values, 1);

		for (i = 0; i < SYSFS_DEVATTR_NUM; i++) {

			dev_attr = sysfs_get_classdev_attr(dev, sysfs_devattrs[i].name);
			if (!dev_attr) {
				perror("sysfs_get_classdev_attr");
				rc = -1;
				break;
			}
			if (sysfs_read_attribute(dev_attr)) {
				perror("sysfs_read_attribute");
				rc = -1;
				break;
			}
			rc = sysfs_devattrs[i].handler(dev_attr->value, &sysfs_devattr_values, i);

			//sysfs_close_attribute(dev_attr);

			if (rc < 0)
				break;
		}

		if (rc < 0)
			goto do_next;

		if (check_ifflags(sysfs_devattr_values.value[SYSFS_DEVATTR_FLAGS].ulong,
				  device->name != NULL) < 0)
			goto do_next;

		if (!sysfs_devattr_values.value[SYSFS_DEVATTR_ADDR_LEN].ulong)
			goto do_next;

		if (device->sysfs->value[SYSFS_DEVATTR_IFINDEX].ulong) {
			if (device->sysfs->value[SYSFS_DEVATTR_FLAGS].ulong & IFF_RUNNING)
				goto do_next;
		}

		sysfs_devattr_values.ifname = strdup(dev->name);
		if (!sysfs_devattr_values.ifname) {
			perror("malloc");
			goto out;
		}

		sysfs_devattr_values_init(device->sysfs, 1);
		memcpy(device->sysfs, &sysfs_devattr_values, sizeof(*device->sysfs));
		sysfs_devattr_values_init(&sysfs_devattr_values, 0);

		if (device->sysfs->value[SYSFS_DEVATTR_FLAGS].ulong & IFF_RUNNING)
			break;

		continue;
do_next:
		sysfs_devattr_values_init(&sysfs_devattr_values, 1);
	}

	//sysfs_close_list(dev_list);
	sysfs_close_class(cls_net);

	device->ifindex = device->sysfs->value[SYSFS_DEVATTR_IFINDEX].ulong;
	device->name = device->sysfs->ifname;

	return 0;
out:
	return -1;
}

int set_device_broadcast_sysfs(struct device *device, unsigned char *ba, size_t balen)
{
	struct sysfs_devattr_values *v;
	if (!device)
		return -1;
	v = device->sysfs;
	if (!v)
		return -1;
	if (v->value[SYSFS_DEVATTR_ADDR_LEN].ulong != balen)
		return -1;
	memcpy(ba, v->value[SYSFS_DEVATTR_BROADCAST].ptr, balen);
	return 0;
}

