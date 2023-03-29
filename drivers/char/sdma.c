/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Sun Feb 07 08:45:25 2021
 */
#define pr_fmt(fmt) "SDMA:" fmt

#include <linux/hisi_sdma.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>

#define SDMA_DEVICE_NAME "sdma"

struct sdma_sq_entry {

};

struct sdma_cq_entry {

};

struct sdma_channel {

};

struct sdma_device {

};

int sdma_memcpy(void *des, const void *src, size_t len)
{
	return 0;
}

static int sdma_device_probe(struct platform_device *pdev)
{
	return 0;
}

static int sdma_device_remove(struct platform_device *pdev)
{
	return 0;
}

static void sdma_device_shutdown(struct platform_device *pdev)
{
	return;
}

static const struct of_device_id sdma_of_match[] = {
	{ .compatible = "hisilicon,sdma" },
	{ }
};
MODULE_DEVICE_TABLE(of, sdma_of_match);

static struct platform_driver sdma_driver = {
	.probe    = sdma_device_probe,
	.remove   = sdma_device_remove,
	.shutdown = sdma_device_shutdown,
	.driver   = {
		.name           = SDMA_DEVICE_NAME,
		.of_match_table = sdma_of_match,
	},
};
module_platform_driver(sdma_driver);

MODULE_AUTHOR("Wang Wensheng <wangwensheng4@huawei.com>");
MODULE_LICENSE("GPL v2");
