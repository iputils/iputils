/*
 * arping.h
 *
 * part of iputils package.
 */

struct sysfs_devattr_values;

struct device {
	char *name;
	int ifindex;
#ifndef WITHOUT_IFADDRS
	struct ifaddrs *ifa;
#endif
#ifndef USE_SYSFS
	struct sysfs_devattr_values *sysfs;
#endif
};

extern int check_ifflags(unsigned int ifflags, int fatal);
