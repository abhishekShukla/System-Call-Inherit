#ifndef IOCTL_PROC_H
#define IOCTL_PROC_H

#include <linux/ioctl.h>
#define DEVICE_NUM 121

#define IOCTL_SET_VECTOR _IOR(DEVICE_NUM, 1, char*)
#define IOCTL_REMOVE _IOR(DEVICE_NUM, 2, char*)

#endif
