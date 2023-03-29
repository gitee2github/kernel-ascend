/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Sun Feb 07 09:11:30 2021
 */

#ifndef __HISI_SDMA_H__
#define __HISI_SDMA_H__

#include <linux/types.h>
#include <linux/errno.h>

struct sdma_task_desc {
	unsigned long	src_addr;
	unsigned long	dst_addr;
	size_t		len;
};
#define IOCTL_SDMA_MEM_COPY		_IOW('s', 1, struct sdma_task_desc)

#ifdef CONFIG_HISI_SDMA

int sdma_memcpy(void *des, const void *src, size_t len);

#else

int sdma_memcpy(void *des, const void *src, size_t len)
{
	return -ENODEV;
}

#endif

#endif
