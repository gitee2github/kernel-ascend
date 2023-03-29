/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Sun Feb 07 08:45:25 2021
 */
#define pr_fmt(fmt) "SDMA:" fmt

#include <linux/hisi_sdma.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/bitmap.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/dma-iommu.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#define SDMA_DEVICE_NAME "sdma"

/* SDMA_CH_REGS */
#define SDMAM_CH_CTRL_REG		0x0000
#define SDMAM_CH_IIDR_REG		0x0004
#define SDMAM_CH_TYPER_REG		0x0008
#define SDMAM_CH_BYPASS_CTRL_REG	0x0014

#define SDMAM_IRQ_STATUS_REG		0x000c
#define SDMAM_IRQ_CTRL_REG		0x0010
#define SDMAM_IRQ_IOC_MASK		(1U << 16)
#define SDMAM_IRQ_IOE_MASK		(1U << 17)
#define SDMAM_IRQ_ERR_MASK		(0xFFU << 20)

#define SDMAM_CH_SQBASER_L_REG		0x0040
#define SDMAM_CH_SQBASER_H_REG		0x0044
#define SDMAM_CH_SQ_ATTR_REG		0x0048
#define SDMAM_CH_SQTDBR_REG		0x004c
#define SDMAM_CH_SQHDBR_REG		0x0050

#define SDMAM_CH_CQBASER_L_REG		0x0080
#define SDMAM_CH_CQBASER_H_REG		0x0084
#define SDMAM_CH_CQ_ATTR_REG		0X0088
#define SDMAM_CH_CQTDBR_REG		0x008c
#define SDMAM_CH_CQHDBR_REG		0x0090

/* SDMA_COMMON_REGS */
#define SDMA_COMMON_DMA_AXUSER_REG0	0x0FE0
#define SDMA_COMMON_DMA_AXUSER_REG1	0x0FE4
#define SDMA_COMMON_DMA_AXUSER_REG2	0x0FE8
#define SDMA_DFX_FEATURE_EN_REG		0x0FFC

#define SDMA_IOMEM_SIZE			0x10000
#define SDMA_CHANNELL_IOMEM_SIZE	0x1000

#define SDMA_SQ_ENTRY_SIZE		32UL
#define SDMA_CQ_ENTRY_SIZE		16UL

/* must be pow of 2 */
#define SDMA_SQ_LENGTH			(1U << 10)
#define SDMA_CQ_LENGTH			(1U << 10)
#define SDMA_SQ_SIZE 			(SDMA_SQ_ENTRY_SIZE * SDMA_SQ_LENGTH)
#define SDMA_CQ_SIZE 			(SDMA_CQ_ENTRY_SIZE * SDMA_CQ_LENGTH)

#define SDMA_MAX_COPY_SIZE		0x100000000UL
#define SDMA_COPY_SIZE_MASK		0xFFFFFFFFUL

#define SDMA_MAX_CHANNEL_NUM		16

static u32 sdma_queue_count(u32 head, u32 tail, u32 len)
{
	return (tail - head) & (len - 1);
}

struct sdma_sq_entry {
	u32 opcode          : 8;
	u32 ie              : 1;
	u32 sssv            : 1;
	u32 dssv            : 1;
	u32 sns             : 1;
	u32 dns             : 1;
	u32 qos             : 4;
	u32 sro             : 1;
	u32 dro             : 1;
	u32 partid          : 4;
	u32 mpamns          : 1;
	u32 reserved0       : 8;
	u32 src_streamid    : 16;
	u32 src_substreamid : 16;
	u32 dst_streamid    : 16;
	u32 dst_substreamid : 16;
	u32 length;
	union {
		u64 src_addr;
		struct {
			u32 src_addr_l;
			u32 src_addr_h;
		};
	};
	union {
		u64 dst_addr;
		struct {
			u32 dst_addr_l;
			u32 dst_addr_h;
		};
	};
};

struct sdma_cq_entry {
	u32 reserved1;
	u32 reserved2;
	u32 sqhd      : 16;
	u32 reserved3 : 16;
	u32 reserved4 : 16;
	u32 vld       : 1;
	u32 status    : 15;
};

struct sdma_channel {
	u16			idx;
	u16			cq_vld;
	struct sdma_device	*pdev;

	u16			sq_head;
	u16			sq_tail;
	u16			cq_head;
	u16			cq_tail;

	/* must be page-aligned and continuous physical memory */
	struct sdma_sq_entry	*sq_base;
	struct sdma_cq_entry	*cq_base;

	/* used for discrete copy, pre-alloc the buffer */
	unsigned long		*src_addr;
	unsigned long		*dst_addr;
	unsigned long		*len;

	void __iomem *io_base;
};

#define SDMA_DEVICE_NAME_LENGTH_MAX 20
struct sdma_device {
	u16			idx;
	u16			nr_channel;
	spinlock_t		channel_lock;
	struct sdma_channel	*channels;
	DECLARE_BITMAP(channel_map, SDMA_MAX_CHANNEL_NUM);

	struct platform_device	*pdev;
	struct miscdevice	miscdev;

	u32			streamid;
	void __iomem		*io_base;

	char			name[SDMA_DEVICE_NAME_LENGTH_MAX];
};

#define MAX_SDMA_DEVICE_NR 4
static struct file_operations sdma_core_fops;
static struct {
	int			sdma_device_num;
	struct sdma_device	*sdma_devices[MAX_SDMA_DEVICE_NR];
	struct miscdevice	miscdev;
} sdma_core_device = {
	.sdma_device_num = 0,
	.sdma_devices = {
		[0 ... MAX_SDMA_DEVICE_NR - 1] = NULL,
	},

	.miscdev.minor = MISC_DYNAMIC_MINOR,
	.miscdev.fops = &sdma_core_fops,
	.miscdev.name = "sdma",
};

static void sdma_device_add(struct sdma_device *psdma_dev)
{
	int ret;
	if (!sdma_core_device.sdma_device_num) {
		sdma_core_device.miscdev.minor = MISC_DYNAMIC_MINOR;
		ret = misc_register(&sdma_core_device.miscdev);
		if (ret) {
			pr_err("register misc device for sdma core failed, %d\n", ret);
			return;
		}
	}

	sdma_core_device.sdma_device_num++;
	sdma_core_device.sdma_devices[psdma_dev->idx] = psdma_dev;
}

static void sdma_device_delete(struct sdma_device *psdma_dev)
{
	if (!sdma_core_device.sdma_devices[psdma_dev->idx])
		return;

	sdma_core_device.sdma_device_num--;
	sdma_core_device.sdma_devices[psdma_dev->idx] = NULL;

	if (!sdma_core_device.sdma_device_num)
		misc_deregister(&sdma_core_device.miscdev);
}

static struct sdma_device *sdma_device_select(void)
{
	int idx = numa_node_id();
	if (idx < 0 || idx >= MAX_SDMA_DEVICE_NR)
		idx = 0;
	return sdma_core_device.sdma_devices[idx];
}

struct sdma_hardware_info {
	unsigned long	channel_map;
	u64		base_addr; /* physical address */
};

#define CHANNEL_MAP_PROP "channel_map"

static int of_sdma_collect_info(struct platform_device *pdev, struct sdma_hardware_info *info)
{
	int ret;
	u32 channel_map;
	struct resource res;
	struct device_node *np = pdev->dev.of_node;

	ret = of_property_read_u32(np, CHANNEL_MAP_PROP, &channel_map);
	if (ret < 0) {
		pr_err("get " CHANNEL_MAP_PROP " info from dtb failed, %d\n", ret);
		return ret;
	}
	info->channel_map = channel_map;

	ret = of_address_to_resource(np, 0, &res);
	if (ret < 0) {
		pr_err("get io_base info from dtb failed, %d\n", ret);
		return ret;
	}
	info->base_addr = res.start;
	if (resource_size(&res) != SDMA_IOMEM_SIZE)
		pr_warn("reg size %#llx check failed, use %#x\n", resource_size(&res), SDMA_IOMEM_SIZE);

	return 0;
}

#ifdef CONFIG_ACPI
static int acpi_sdma_collect_info(struct platform_device *pdev, struct sdma_hardware_info *info)
{
	int ret;
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);
	u32 channel_map;
	u64 io_base;

	ret = acpi_dev_prop_read_single(adev, CHANNEL_MAP_PROP, DEV_PROP_U32, &channel_map);
	if (ret) {
		pr_err("ACPI get " CHANNEL_MAP_PROP " info failed, %d\n", ret);
		return ret;
	}
	info->channel_map = channel_map;
	ret = acpi_dev_prop_read_single(adev, "reg_base", DEV_PROP_U64, &io_base);
	if (ret) {
		pr_err("ACPI get reg_base info failed, %d\n", ret);
		return ret;
	}
	info->base_addr = io_base;

	return 0;
}
#else
static int acpi_sdma_collect_info(struct platform_device *pdev, struct sdma_hardware_info *info)
{
	return -EOPNOTSUPP;
}
#endif

static int sdma_channel_alloc_sq_cq(struct sdma_channel *pchan)
{
	unsigned long *buf;

	pchan->sq_base = (struct sdma_sq_entry *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
								  get_order(SDMA_SQ_SIZE));
	if (!pchan->sq_base) {
		pr_err("channel%d: alloc sq_memory failed\n", pchan->idx);
		return -ENOMEM;
	}

	pchan->cq_base = (struct sdma_cq_entry *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
								  get_order(SDMA_CQ_SIZE));
	if (!pchan->cq_base) {
		pr_err("channel%d: alloc cq_memory failed\n", pchan->idx);
		free_pages((unsigned long)pchan->sq_base, get_order(SDMA_SQ_SIZE));
		return -ENOMEM;
	}

	buf = vmalloc(sizeof(unsigned long) * SDMA_SQ_LENGTH * 3);
	if (!buf) {
		pr_err("channel%d: alloc user_buf failed\n", pchan->idx);
		free_pages((unsigned long)pchan->sq_base, get_order(SDMA_SQ_SIZE));
		free_pages((unsigned long)pchan->cq_base, get_order(SDMA_CQ_SIZE));
		return -ENOMEM;
	}
	pchan->src_addr = buf;
	pchan->dst_addr = buf + SDMA_SQ_LENGTH;
	pchan->len      = buf + SDMA_SQ_LENGTH * 2;

	return 0;
}

static void sdma_free_all_sq_cq(struct sdma_device *psdma_dev)
{
	int i;
	struct sdma_channel *pchan;

	for (i = psdma_dev->nr_channel - 1; i >= 0; i--) {
		pchan = psdma_dev->channels + i;
		free_pages((unsigned long)pchan->sq_base, get_order(SDMA_SQ_SIZE));
		free_pages((unsigned long)pchan->cq_base, get_order(SDMA_CQ_SIZE));
		vfree(pchan->src_addr);
	}
}

static void sdma_channel_set_val_mask_shift(struct sdma_channel *pchan, int reg, u32 val, u32 mask, u32 shift)
{
	u32 reg_val = readl(pchan->io_base + reg);
	reg_val = (reg_val & ~(mask << shift)) | ((val & mask) << shift);
	writel(reg_val, pchan->io_base + reg);
	return;
}

static u32 sdma_channel_get_val_mask_shift(struct sdma_channel *pchan, int reg, u32 mask, u32 shift)
{
	u32 reg_val = readl(pchan->io_base + reg);
	return (reg_val >> shift) & mask;
}

static void sdma_channel_set_pause(struct sdma_channel *pchan)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 1, 1, 1);
}

static bool sdma_channel_is_paused(struct sdma_channel *pchan)
{
	return sdma_channel_get_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 0xF, 16) == 3;
}

static bool sdma_channel_is_idle(struct sdma_channel *pchan)
{
	return sdma_channel_get_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 0xF, 16) == 0;
}

static bool sdma_channel_is_quiescent(struct sdma_channel *pchan)
{
	return sdma_channel_get_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 1, 31) == 1;
}

static void sdma_channel_write_reset(struct sdma_channel *pchan)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 1, 1, 3);
}

static void sdma_channel_enable(struct sdma_channel *pchan)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 1, 1, 0);
}

static void sdma_channel_disable(struct sdma_channel *pchan)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_CTRL_REG, 0, 1, 0);
}

static void sdma_channel_set_sq_size(struct sdma_channel *pchan, u32 size)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_SQ_ATTR_REG, size, 0xFFFF, 0);
}

static void sdma_channel_set_cq_size(struct sdma_channel *pchan, u32 size)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_CQ_ATTR_REG, size, 0xFFFF, 0);
}

static void sdma_channel_set_sq_tail(struct sdma_channel *pchan, u32 val)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_SQTDBR_REG, val, 0xFFFF, 0);
}

static u32 sdma_channel_get_sq_head(struct sdma_channel *pchan)
{
	return sdma_channel_get_val_mask_shift(pchan, SDMAM_CH_SQHDBR_REG, 0xFFFF, 0);
}

static void sdma_channel_set_cq_head(struct sdma_channel *pchan, u32 val)
{
	sdma_channel_set_val_mask_shift(pchan, SDMAM_CH_CQHDBR_REG, val, 0xFFFF, 0);
}

static u32 sdma_channel_get_cq_tail(struct sdma_channel *pchan)
{
	return sdma_channel_get_val_mask_shift(pchan, SDMAM_CH_CQTDBR_REG, 0xFFFF, 0);
}

static void sdma_channel_init(struct sdma_channel *pchan)
{
	void __iomem *io_base = pchan->io_base;
	u64 sq_addr = virt_to_phys(pchan->sq_base);
	u64 cq_addr = virt_to_phys(pchan->cq_base);

	writel(sq_addr & 0xFFFFFFFF, io_base + SDMAM_CH_SQBASER_L_REG);
	writel(sq_addr >> 32, io_base + SDMAM_CH_SQBASER_H_REG);
	writel(cq_addr & 0xFFFFFFFF, io_base + SDMAM_CH_CQBASER_L_REG);
	writel(cq_addr >> 32, io_base + SDMAM_CH_CQBASER_H_REG);

	sdma_channel_set_sq_size(pchan, SDMA_SQ_LENGTH - 1);
	sdma_channel_set_cq_size(pchan, SDMA_CQ_LENGTH - 1);
	sdma_channel_set_sq_tail(pchan, 0);
	sdma_channel_set_cq_head(pchan, 0);

	pchan->cq_vld = 1;
	sdma_channel_enable(pchan);
}

static void sdma_channel_reset(struct sdma_channel *pchan)
{
	int i = 0;

	sdma_channel_set_pause(pchan);
	while (!sdma_channel_is_paused(pchan))
		if (++i > 10) {
			pr_warn("the channel cannot get paused\n");
			break;
		}

	i = 0;
	while (!sdma_channel_is_quiescent(pchan))
		if (++i > 10) {
			pr_warn("the channel cannot get quiescent\n");
			break;
		}

	i = 0;
	sdma_channel_write_reset(pchan);
	while (!sdma_channel_is_idle(pchan))
		if (++i > 10) {
			pr_warn("the channel cannot get idle\n");
			break;
		}
	sdma_channel_disable(pchan);

	pchan->sq_head = pchan->sq_tail = pchan->cq_head = pchan->cq_tail = 0;
	sdma_channel_init(pchan);
}

static void sdma_destroy_channels(struct sdma_device *psdma_dev)
{
	sdma_free_all_sq_cq(psdma_dev);
	kfree(psdma_dev->channels);
}

static int sdma_init_channels(struct sdma_device *psdma_dev, struct sdma_hardware_info *info)
{
	int ret = 0;
	int i, nr_channel;
	struct sdma_channel *pchan;

	nr_channel = bitmap_weight(&info->channel_map, BITS_PER_LONG);
	if (!nr_channel || nr_channel > SDMA_MAX_CHANNEL_NUM) {
		pr_err("channel count (%d) invalid\n", nr_channel);
		return -ENODEV;
	}
	psdma_dev->channels = kzalloc(sizeof(struct sdma_channel) * nr_channel, GFP_KERNEL);
	if (!psdma_dev->channels)
		return -ENOMEM;

	psdma_dev->nr_channel = 0;
	for (i = 0; psdma_dev->nr_channel < nr_channel; i++) {
		if (!(info->channel_map & (1U << i)))
			continue;

		pchan = psdma_dev->channels + psdma_dev->nr_channel;
		pchan->idx = psdma_dev->nr_channel;
		pchan->pdev = psdma_dev;

		ret = sdma_channel_alloc_sq_cq(pchan);
		if (ret < 0)
			goto err_out;

		psdma_dev->nr_channel++;
		pchan->io_base = psdma_dev->io_base + i * SDMA_CHANNELL_IOMEM_SIZE;
		sdma_channel_disable(pchan);
		sdma_channel_init(pchan);

		pr_info("hardware channel%d probed, idx %d\n", i, pchan->idx);
	}

	bitmap_set(psdma_dev->channel_map, 0, nr_channel);

	return 0;

err_out:
	sdma_destroy_channels(psdma_dev);

	return ret;
}

static struct file_operations sdma_fops;

static int sdma_device_probe(struct platform_device *pdev)
{
	int ret;
	struct sdma_hardware_info info;
	struct sdma_device *psdma_dev;

	if (!pdev->dev.bus) {
		pr_debug("the sdma dev bus is NULL\n");
		return -EPROBE_DEFER;
	}

	if (!pdev->dev.bus->iommu_ops) {
		pr_debug("defer probe sdma device\n");
		return -EPROBE_DEFER;
	}

	psdma_dev = kzalloc(sizeof(*psdma_dev), GFP_KERNEL);
	if (!psdma_dev) {
		pr_err("alloc sdma_device failed\n");
		return -ENOMEM;
	}

	psdma_dev->pdev = pdev;
	dev_set_drvdata(&pdev->dev, psdma_dev);

	if (acpi_disabled)
		ret = of_sdma_collect_info(pdev, &info);
	else
		ret = acpi_sdma_collect_info(pdev, &info);
	if (ret < 0) {
		pr_err("collect device info failed, %d\n", ret);
		goto free_dev;
	}

	psdma_dev->io_base = ioremap(info.base_addr, SDMA_IOMEM_SIZE);
	if (!psdma_dev->io_base) {
		pr_err("ioremap failed\n");
		ret = -ENOMEM;
		goto free_dev;
	}

	ret = sdma_init_channels(psdma_dev, &info);
	if (ret < 0)
		goto unmap_iobase;

	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
	if (ret) {
		pr_err("iommu failed to init iopf, %d\n", ret);
		goto destroy_channels;
	}

	ret = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (ret) {
		pr_err("iommu failed to init sva, %d\n", ret);
		goto disable_iopf;
	}

	/* FIXME:the index of sdma_device should be set according to the numa ID */
	psdma_dev->idx = sdma_core_device.sdma_device_num;
	psdma_dev->miscdev.minor = MISC_DYNAMIC_MINOR;
	psdma_dev->miscdev.fops = &sdma_fops;
	psdma_dev->miscdev.name = psdma_dev->name;
	snprintf(psdma_dev->name, SDMA_DEVICE_NAME_LENGTH_MAX, "sdma%d", psdma_dev->idx);
	ret = misc_register(&psdma_dev->miscdev);
	if (ret) {
		pr_err("register misc device failed, %d\n", ret);
		goto disable_sva;
		}

	psdma_dev->streamid = pdev->dev.iommu->fwspec->ids[0];
	spin_lock_init(&psdma_dev->channel_lock);

	sdma_device_add(psdma_dev);
	pr_info("%s device probe success\n", psdma_dev->name);

	return 0;

disable_sva:
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
disable_iopf:
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);
destroy_channels:
	sdma_destroy_channels(psdma_dev);
unmap_iobase:
	iounmap(psdma_dev->io_base);
free_dev:
	kfree(psdma_dev);

	return ret;
}

static int sdma_device_remove(struct platform_device *pdev)
{
	struct sdma_device *psdma_dev = dev_get_drvdata(&pdev->dev);

	misc_deregister(&psdma_dev->miscdev);

	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_IOPF);

	sdma_destroy_channels(psdma_dev);

	iounmap(psdma_dev->io_base);

	sdma_device_delete(psdma_dev);

	kfree(psdma_dev);

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

static const struct acpi_device_id sdma_acpi_match[] = {
	{"SDMA1000", 0},
	{"SDMA2000", 1},
	{"SDMA3000", 2},
	{"SDMA4000", 3},
	{},
};
MODULE_DEVICE_TABLE(acpi, sdma_acpi_match);

static struct platform_driver sdma_driver = {
	.probe    = sdma_device_probe,
	.remove   = sdma_device_remove,
	.shutdown = sdma_device_shutdown,
	.driver   = {
		.name           = SDMA_DEVICE_NAME,
		.of_match_table = sdma_of_match,
		.acpi_match_table = ACPI_PTR(sdma_acpi_match),
	},
};
module_platform_driver(sdma_driver);

static struct sdma_channel *sdma_get_channel(struct sdma_device *pdev)
{
	int idx;
	struct sdma_channel *pchan = NULL;

	if (!pdev || !pdev->nr_channel)
		return NULL;

	spin_lock(&pdev->channel_lock);
	idx = find_first_bit(pdev->channel_map, pdev->nr_channel);
	if (idx != pdev->nr_channel) {
		bitmap_clear(pdev->channel_map, idx, 1);
		pchan = pdev->channels + idx;
	}
	spin_unlock(&pdev->channel_lock);

	return pchan;
}

static void sdma_put_channel(struct sdma_channel *pchan)
{
	struct sdma_device *pdev = pchan->pdev;

	spin_lock(&pdev->channel_lock);
	bitmap_set(pdev->channel_map, pchan->idx, 1);
	spin_unlock(&pdev->channel_lock);
}

static void sdma_channel_submit_task(struct sdma_channel *pchan, unsigned long dst_addr[],
				     unsigned long src_addr[], unsigned long len[],
				     unsigned int count, int pasid)
{
	int i;
	u16 sq_tail = pchan->sq_tail;
	struct sdma_sq_entry *entry = NULL;

	for (i = 0; i < count; i++) {
		entry = pchan->sq_base + sq_tail;

		entry->src_streamid = pchan->pdev->streamid;
		entry->dst_streamid = pchan->pdev->streamid;
		entry->src_addr     = (u64)src_addr[i];
		entry->dst_addr     = (u64)dst_addr[i];
		entry->length       = len[i];
		entry->sns          = 1;
		entry->dns          = 1;
		entry->ie           = 0;
		entry->partid       = 0;
		entry->mpamns       = 1;
		if (pasid) {
			entry->sssv            = 1;
			entry->dssv            = 1;
			entry->src_substreamid = pasid;
			entry->dst_substreamid = pasid;
		} else {
			entry->sssv = 0;
			entry->dssv = 0;
		}

		sq_tail = (sq_tail + 1) & (SDMA_SQ_LENGTH - 1);
	}

	if (!entry)
		return;

	entry->ie = 1;

	dmb(sy);
	sdma_channel_set_sq_tail(pchan, sq_tail);
	pchan->sq_tail = sq_tail;
}

static int sdma_channel_wait(struct sdma_channel *pchan)
{
	int ret = 0, i = 0;
	u32 irq_reg, cq_head, cq_tail, cq_count;
	struct sdma_cq_entry *cq_entry;

	while (i++ < 10000000) {
		cond_resched();
		dsb(sy);

		irq_reg = readl(pchan->io_base + SDMAM_IRQ_STATUS_REG);

		if (irq_reg & SDMAM_IRQ_IOC_MASK) {
			writel(irq_reg, pchan->io_base + SDMAM_IRQ_STATUS_REG);

			cq_head = pchan->cq_head;
			cq_tail = sdma_channel_get_cq_tail(pchan);
			cq_count = sdma_queue_count(cq_head, cq_tail, SDMA_CQ_LENGTH);
			if (!cq_count) {
				pr_err("unexpected complete irq\n");
				return -EFAULT;
			}

			for (; cq_count; cq_count--) {
				cq_entry = pchan->cq_base + cq_head;
				if (cq_entry->vld != pchan->cq_vld || cq_entry->status) {
					pr_err("cq_entry invalid, vld: %u, cq_vld: %u, status: %u\n",
						cq_entry->vld, pchan->cq_vld, cq_entry->status);
					ret = -EFAULT;
				}
				if (++cq_head == SDMA_CQ_LENGTH) {
					pchan->cq_vld ^= 1;
					cq_head = 0;
				}
			}

			pchan->cq_head = cq_head;
			sdma_channel_set_cq_head(pchan, cq_head);
			pchan->sq_head = sdma_channel_get_sq_head(pchan);
			pchan->cq_tail = cq_tail;

			return ret;
		} else if (irq_reg & SDMAM_IRQ_IOE_MASK) {
			writel(irq_reg, pchan->io_base + SDMAM_IRQ_STATUS_REG);
			pr_err("sdma ioe interrupt occur, status: %#x\n", irq_reg);

			cq_tail = sdma_channel_get_cq_tail(pchan);
			if (cq_tail < pchan->cq_head)
				pchan->cq_vld ^= 1;
			pchan->cq_head = pchan->cq_tail = cq_tail;
			pchan->sq_head = sdma_channel_get_sq_head(pchan);

			return -EFAULT;
		}
	}

	pr_err("cannot wait for a complete or error signal\n");
	sdma_channel_reset(pchan);

	return -EFAULT;
}

static int sdma_serial_copy(struct sdma_device *psdma_dev, unsigned long dst_addr[],
			    unsigned long src_addr[], size_t len[], unsigned int count,
			    int pasid)
{
	int ret;
	struct sdma_channel *pchan;

	if (count >= SDMA_SQ_LENGTH || !count) {
		pr_err("invalid copy task count\n");
		return -EINVAL;
	}

	pchan = sdma_get_channel(psdma_dev);
	if (!pchan) {
		pr_err("no channel left\n");
		return -ENODEV;
	}

	sdma_channel_submit_task(pchan, dst_addr, src_addr, len, count, pasid);
	ret = sdma_channel_wait(pchan);

	sdma_put_channel(pchan);

	return ret;
}

struct file_open_data {
	int			pasid;
	struct sdma_device	*psdma_dev;
	struct iommu_sva *sva;
};

static int __do_sdma_open(struct sdma_device *psdma_dev, struct file *file)
{
	void *ret;
	int pasid;
	struct file_open_data *data;

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = iommu_sva_bind_device(&psdma_dev->pdev->dev, current->mm, NULL);
	if (IS_ERR(ret)) {
		pr_err("failed to bind task to device, %ld\n", PTR_ERR(ret));
		kfree(data);
		return PTR_ERR(ret);
	}

	data->sva = ret;
	data->pasid = pasid;
	data->psdma_dev = psdma_dev;
	file->private_data = data;

	return 0;
}

static int sdma_dev_open(struct inode *inode, struct file *file)
{
	struct sdma_device *psdma_dev = container_of(file->private_data, struct sdma_device, miscdev);

	return __do_sdma_open(psdma_dev, file);
}

static int sdma_core_open(struct inode *inode, struct file *file)
{
	struct sdma_device *psdma_dev = sdma_device_select();
	if (!psdma_dev) {
		pr_err("cannot find a sdma device automatically\n");
		return -ENODEV;
	}

	return __do_sdma_open(psdma_dev, file);
}

static int sdma_dev_release(struct inode *inode, struct file *file)
{
	/* We don't unbind current process since other device may use it */
	kfree(file->private_data);

	return 0;
}

struct pin_pages_data {
	unsigned long start;
	unsigned long len;
	unsigned int nr_pages;
	struct page **pages;
};

struct sdma_pin_pages_data {
	struct pin_pages_data src_data;
	struct pin_pages_data dst_data;
};

static void __sdma_unpin_pages(struct pin_pages_data *data)
{
	int nr_pages = data->nr_pages;
	while (nr_pages--)
		put_page(data->pages[nr_pages]);
	kfree(data->pages);
}

static int __sdma_pin_pages(struct pin_pages_data *data)
{
	int nr_pages, ret;
	unsigned long start, end;
	struct page **pages;

	start = ALIGN_DOWN(data->start, PAGE_SIZE);
	end = PAGE_ALIGN(data->start + data->len);
	nr_pages = (end - start) / PAGE_SIZE;
	pages = kmalloc(sizeof(*pages) * nr_pages, GFP_KERNEL);
	if (!pages) {
		pr_info("alloc pin pages array failed\n");
		return -ENOMEM;
	}

	ret = get_user_pages_fast(data->start, nr_pages, 1, pages);
	if (ret < nr_pages && ret >= 0) {
		pr_info("pin pages failed, ret:%d, expected:%d\n", ret, nr_pages);
		while (ret--)
			put_page(pages[ret]);
		ret = -EFAULT;
		goto err;
	} else if (ret < 0) {
		pr_info("pin pages failed, %d\n", ret);
		goto err;
	}

	data->nr_pages = nr_pages;
	data->pages = pages;

	return 0;
err:
	kfree(pages);
	return ret;
}

static int sdma_pin_pages(struct sdma_pin_pages_data *data)
{
	int ret;

	ret = __sdma_pin_pages(&data->src_data);
	if (ret < 0) {
		pr_info("pin src pages failed, %d\n", ret);
		return ret;
	}

	ret = __sdma_pin_pages(&data->dst_data);
	if (ret < 0) {
		__sdma_unpin_pages(&data->src_data);
		return ret;
	}

	return 0;
}

static void sdma_unpin_pages(struct sdma_pin_pages_data *data)
{
	__sdma_unpin_pages(&data->dst_data);
	__sdma_unpin_pages(&data->src_data);
}

static int ioctl_sdma_mem_copy(struct file *file, unsigned long arg)
{
	int ret;
	size_t len;
	unsigned long dst, src;
	struct sdma_task_desc desc;
	struct file_open_data *data = file->private_data;
	struct sdma_pin_pages_data pin_data;

	if (copy_from_user(&desc, (struct sdma_task_desc __user *)arg, sizeof(desc))) {
		pr_err("get user param failed\n");
		return -EFAULT;
	}

	len = desc.len;
	dst = desc.dst_addr;
	src = desc.src_addr;

	if (!dst || !src || !len || len > SDMA_MAX_COPY_SIZE) {
		pr_err("invalid input\n");
		return -EINVAL;
	}
	if (unlikely(len == SDMA_MAX_COPY_SIZE))
		len = 0;

	pin_data.src_data.start = desc.src_addr;
	pin_data.src_data.len = desc.len;
	pin_data.dst_data.start = desc.dst_addr;
	pin_data.dst_data.len = desc.len;
	ret = sdma_pin_pages(&pin_data);
	if (ret < 0)
		return ret;

	ret = sdma_serial_copy(data->psdma_dev, &dst, &src, &len, 1, data->pasid);
	sdma_unpin_pages(&pin_data);

	return ret;
}

static int ioctl_sdma_discrete_copy(struct file *file, unsigned long arg)
{
	int ret;
	struct sdma_channel *pchan;
	struct sdma_discrete_task desc;
	struct file_open_data *data = file->private_data;
	unsigned long *src_addr, *dst_addr, *len, count;

	if (copy_from_user(&desc, (struct sdma_discrete_task __user *)arg, sizeof(desc))) {
		pr_err("get user param failed\n");
		return -EFAULT;
	}

	count = desc.count;
	if (!desc.dst_addr || !desc.src_addr || !desc.len ||
	    !count || count > SDMA_SQ_LENGTH) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	pchan = sdma_get_channel(data->psdma_dev);
	if (!pchan) {
		pr_err("no channel left\n");
		return -ENODEV;
	}

	src_addr = pchan->src_addr;
	if (copy_from_user(src_addr, desc.src_addr, sizeof(unsigned long) * count)) {
		pr_err("get src_addr from user failed\n");
		ret = -EFAULT;
		goto out;
	}

	dst_addr = pchan->dst_addr;
	if (copy_from_user(dst_addr, desc.dst_addr, sizeof(unsigned long) * count)) {
		pr_err("get dst_addr from user failed\n");
		ret = -EFAULT;
		goto out;
	}

	len = pchan->len;
	if (copy_from_user(len, desc.len, sizeof(unsigned long) * count)) {
		pr_err("get len from user failed\n");
		ret = -EFAULT;
		goto out;
	}

	sdma_channel_submit_task(pchan, dst_addr, src_addr, len, count, data->pasid);
	ret = sdma_channel_wait(pchan);

out:
	sdma_put_channel(pchan);
	return ret;
}

static long sdma_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case IOCTL_SDMA_MEM_COPY:
		return ioctl_sdma_mem_copy(file, arg);
	case IOCTL_SDMA_DISCRETE_COPY:
		return ioctl_sdma_discrete_copy(file, arg);
	default:
		pr_err("unsupported command\n");
		return -EINVAL;
	}
}

static struct file_operations sdma_fops = {
	.owner          = THIS_MODULE,
	.open           = sdma_dev_open,
	.unlocked_ioctl = sdma_dev_ioctl,
	.release        = sdma_dev_release,
};

static struct file_operations sdma_core_fops = {
	.owner          = THIS_MODULE,
	.open           = sdma_core_open,
	.unlocked_ioctl = sdma_dev_ioctl,
	.release        = sdma_dev_release,
};

MODULE_AUTHOR("Wang Wensheng <wangwensheng4@huawei.com>");
MODULE_LICENSE("GPL v2");
