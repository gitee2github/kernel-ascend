/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2021 Huawei Technologies Co., Ltd
 */

#ifndef __LINUX_BOOTDOT_H
#define __LINUX_BOOTDOT_H

#define BOOTDOT_DEFAULT 0

/* Set by bbox */
#define BOOTDOT_BLKCK_BOOT_VALID 0x76

#if IS_ENABLED(CONFIG_BOOTDOT)
extern int bootdot_init_blk(u32 block_id, u32 magic, u32 execption_id,
			    u32 expect_status);
extern int bootdot_set_blk(u32 block_id, u32 magic, u32 current_status);
extern struct status_block *bootdot_get_blk(u32 block_id);
extern struct bootdot_device *bootdot_device_get(void);
#else
static inline int bootdot_init_blk(u32 block_id, u32 magic, u32 execption_id,
				   u32 expect_status)
{
	return 0;
}
static inline int bootdot_set_blk(u32 block_id, u32 magic, u32 current_status)
{
	return 0;
}
static inline struct status_block *bootdot_get_blk(u32 block_id)
{
	return NULL;
}
static inline struct bootdot_device *bootdot_device_get(void)
{
	return NULL;
}
#endif

#endif /* LINUX_BOOTDOT_H */
