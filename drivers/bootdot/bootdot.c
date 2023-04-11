// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: kernel bootdot
 * Create: 2021-08-05
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/bootdot.h>

/*
 * status block content
 * struct occupy 24B
 */
struct status_block {
	unsigned int magic;
	unsigned char valid;
	unsigned char block_id;
	unsigned char arg_1;
	unsigned char arg_2;
	unsigned int exception_id;
	unsigned int expect_status;
	unsigned int current_status;
	unsigned int reserve;
};

struct bootdot_device {
	unsigned long mem_base;
	unsigned long mem_size;
	unsigned int blk_base;
	unsigned int blk_size;
	unsigned int blk_num;
	unsigned int blk_end;
	unsigned char kernel_blkid;
	unsigned int exception_id;
};

static unsigned long bootdot_phy_base;
static unsigned long bootdot_phy_size;
static bool bootdot_enable;
static u32 blk_id_show;
static struct bootdot_device bootdot;
static DEFINE_SPINLOCK(bootdot_lock);
static struct proc_dir_entry *root_bootdot_dir;

int bootdot_init_blk(u32 block_id, u32 magic, u32 execption_id,
		     u32 expect_status)
{
	struct status_block *blk = NULL;
	unsigned int id_offset;

	if (!bootdot_enable)
		return -ENODEV;

	if (block_id < bootdot.blk_base || block_id > bootdot.blk_end) {
		pr_err("bootdot initblk fail: blk_id[%d] is not in the [%d %d]\n",
				block_id, bootdot.blk_base, bootdot.blk_end);
		return -EINVAL;
	}

	id_offset = block_id - bootdot.blk_base;
	blk = (struct status_block *)(uintptr_t)(bootdot.mem_base +
					id_offset * bootdot.blk_size);

	spin_lock(&bootdot_lock);
	if (blk->current_status != blk->expect_status) {
		pr_err("bootdot initblk: blk-[%d] already has failed, exception=0x%x cur=0x%x, expect=0x%x\n",
				block_id, blk->exception_id, blk->current_status, blk->expect_status);
		spin_unlock(&bootdot_lock);
		return -EINVAL;
	}

	memset((void *)blk, 0, bootdot.blk_size);

	blk->magic = magic;
	blk->valid = BOOTDOT_BLKCK_BOOT_VALID;
	blk->block_id = block_id;
	blk->exception_id = execption_id;
	blk->expect_status = expect_status;
	spin_unlock(&bootdot_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(bootdot_init_blk);

int bootdot_set_blk(u32 block_id, u32 magic, u32 current_status)
{
	struct status_block *blk = NULL;
	unsigned int id_offset;

	if (!bootdot_enable)
		return -ENODEV;

	if (block_id < bootdot.blk_base || block_id > bootdot.blk_end) {
		pr_err("bootdot setblk fail: blk_id[%d] is not in the [%d %d]\n",
				block_id, bootdot.blk_base, bootdot.blk_end);
		return -EINVAL;
	}

	id_offset = block_id - bootdot.blk_base;
	blk = (struct status_block *)(uintptr_t)(bootdot.mem_base +
					id_offset * bootdot.blk_size);
	if (blk->magic != magic) {
		pr_err("bootdot setblk fail: input magic 0x%x, saved magic 0x%x\n", 
				magic, blk->magic);
		return -EINVAL;
	}

	spin_lock(&bootdot_lock);
	blk->current_status = current_status;
	spin_unlock(&bootdot_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(bootdot_set_blk);

struct status_block *bootdot_get_blk(u32 block_id)
{
	if (!bootdot_enable)
		return NULL;

	if (block_id < bootdot.blk_base || block_id > bootdot.blk_end) {
		pr_err("bootdot getblk fail: blk_id[%d] is not in the [%d %d]\n",
				block_id, bootdot.blk_base, bootdot.blk_end);
		return NULL;
	}

	return (struct status_block *)(uintptr_t)(bootdot.mem_base +
					(block_id - bootdot.blk_base) * bootdot.blk_size);

}
EXPORT_SYMBOL_GPL(bootdot_get_blk);

static int blkget_show(struct seq_file *m, void *v)
{
	struct status_block *blk = NULL;
	unsigned int id_offset;

	id_offset = blk_id_show - bootdot.blk_base;
	blk = (struct status_block *)(uintptr_t)(bootdot.mem_base +
					id_offset * bootdot.blk_size);
	seq_printf(m, "blk=%d magic=0x%x exce=0x%x cur=%d expect=%d\n", 
				blk_id_show, blk->magic, blk->exception_id, 
				blk->current_status, blk->expect_status);

	return 0;
}

static ssize_t blkget_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	char *o = NULL;
	u32 block_id;
	int ret = -EFAULT;

	o = kzalloc(count + 1, GFP_KERNEL);
	if (!o)
		return -ENOMEM;

	if (copy_from_user(o, buffer, count))
		goto freeout;

	ret = kstrtouint(o, 10, &block_id);
	if (ret)
		goto freeout;

	if (block_id < bootdot.blk_base || block_id > bootdot.blk_end) {
		ret = -EINVAL;
		goto freeout;
	}

	blk_id_show = block_id;
	ret = count;
freeout:
	kfree(o);
	return ret;
}

static int blkget_open(struct inode *inode, struct file *file)
{
	return single_open(file, blkget_show, PDE_DATA(inode));
}

static const struct proc_ops getblk_proc_fops = {
	.proc_open		= blkget_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
	.proc_write		= blkget_write,
};

static int blkset_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t blkset_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	char *token, *o_free, *o = NULL;
	int i;
	u32 user_param[3];
	int ret = -EFAULT;

	o = kzalloc(count + 1, GFP_KERNEL);
	if (!o)
		return -ENOMEM;
	o_free = o;

	if (copy_from_user(o, buffer, count))
		goto freeout;

	for (i = 0; i < 3; i++) {
		token = strsep(&o, ",");
		if (!token)
			goto freeout;

		ret = kstrtouint(token, 10, &(user_param[i]));
		if (ret)
			goto freeout;
	}

	/* check the end of buffer */
	if (o != NULL) {
		ret = -EINVAL;
		goto freeout;
	}

	ret = bootdot_set_blk(user_param[0], user_param[1], user_param[2]);
	if (ret != 0)
		goto freeout;

	ret = count;
freeout:
	kfree(o_free);
	return ret;
}

static int blkset_open(struct inode *inode, struct file *file)
{
	return single_open(file, blkset_show, PDE_DATA(inode));
}

static const struct proc_ops setblk_proc_fops = {
	.proc_open		= blkset_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
	.proc_write		= blkset_write,
};

static int initblk_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t initblk_write(struct file *file,
		const char __user *buffer, size_t count, loff_t *ppos)
{
	char *token, *o_free, *o = NULL;
	int i;
	u32 user_param[4];
	int ret = -EFAULT;

	o = kzalloc(count + 1, GFP_KERNEL);
	if (!o)
		return -ENOMEM;
	o_free = o;

	if (copy_from_user(o, buffer, count))
		goto freeout;

	for (i = 0; i < 4; i++) {
		token = strsep(&o, ",");
		if (!token)
			goto freeout;

		ret = kstrtouint(token, 10, &(user_param[i]));
		if (ret)
			goto freeout;
	}

	/* check the end of buffer */
	if (o != NULL) {
		ret = -EINVAL;
		goto freeout;
	}

	ret = bootdot_init_blk(user_param[0], user_param[1], user_param[2],
				user_param[3]);
	if (ret != 0)
		goto freeout;

	ret = count;
freeout:
	kfree(o_free);
	return ret;
}

static int initblk_open(struct inode *inode, struct file *file)
{
	return single_open(file, initblk_show, PDE_DATA(inode));
}

static const struct proc_ops initblk_proc_fops = {
	.proc_open		= initblk_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
	.proc_write		= initblk_write,
};

struct bootdot_device *bootdot_device_get(void)
{
	return &bootdot;
}
EXPORT_SYMBOL_GPL(bootdot_device_get);

static void blkid_init(void)
{
	bootdot.blk_base = BOOTDOT_DEFAULT;
	bootdot.kernel_blkid = BOOTDOT_DEFAULT;
	bootdot.exception_id = BOOTDOT_DEFAULT;
}

static int32_t bootdot_show_read(struct seq_file *m, void *v)
{
	struct bootdot_device *bootdot = bootdot_device_get();
	int i;
	struct status_block *blk = NULL;

	seq_printf(m, "bootdot_show, blk_num=%d\n", bootdot->blk_num);
	seq_printf(m, "magic		blockid		exception_id		expect		current\n");

	for (i = 0;i < bootdot->blk_num; ++i) {
		blk = (struct status_block *)(uintptr_t)(bootdot->mem_base +
			       i * bootdot->blk_size);
		seq_printf(m, "0x%08x	%d		0x%08x		%d		%d\n",
				blk->magic, blk->block_id, blk->exception_id, blk->expect_status, blk->current_status);
	}

	return 0;
}

int init_bootdot(void)
{
	/* init bootdot */
	bootdot.mem_base = (unsigned long)ioremap_wc(bootdot_phy_base,
						     bootdot_phy_size);
	if (!bootdot.mem_base) {
		pr_err("bootdot fail: ioremap(bootdot_base) failed\n");
		goto error;
	}
	memset((void *)bootdot.mem_base, 0, bootdot_phy_size);

	/* setup blkid */
	blkid_init();

	bootdot.mem_size = bootdot_phy_size;
	bootdot.blk_size = sizeof(struct status_block);
	bootdot.blk_num = bootdot.mem_size / bootdot.blk_size;
	if (bootdot.blk_num == 0) {
		pr_err("bootdot fail: blk_num %d unexpectedly\n",
						bootdot.blk_num);
		goto error;
	}
	bootdot.blk_end = bootdot.blk_base + bootdot.blk_num - 1;

	pr_info("bootdot probe succ, blk id:[%d, %d]\n",
				bootdot.blk_base, bootdot.blk_end);

	blk_id_show = BOOTDOT_DEFAULT;

	root_bootdot_dir = proc_mkdir("bootdot", NULL);
	if (!root_bootdot_dir) {
		pr_err("bootdot fail: create /proc/bootdot failed\n");
		goto error;
	}

	proc_create("initblk", 0644, root_bootdot_dir, &initblk_proc_fops);
	proc_create("setblk", 0644, root_bootdot_dir, &setblk_proc_fops);
	proc_create("getblk", 0644, root_bootdot_dir, &getblk_proc_fops);
	proc_create_single("bootdot-show", 0444, NULL, bootdot_show_read);

	return 0;
error:
	pr_err("Bootdot: probe failed\n");
	bootdot_enable = false;
	if (bootdot.mem_base)
		iounmap((void *)bootdot.mem_base);
	return -EINVAL;
}

static int bootdot_probe(struct platform_device *pdev)
{
	int err;
	struct device_node *np;
	struct resource r;
	struct device *dev = &pdev->dev;

	np = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!np) {
		pr_err("Bootdot: Cannot find reserved memory!\n");
		return -EINVAL;
	}

	err = of_address_to_resource(np, 0, &r);
	if (err) {
		pr_err("Bootdot: Cannot address to resource for reserved memory!\n");
		return -ENOMEM;
	}

	bootdot_phy_base = r.start;
	bootdot_phy_size = resource_size(&r);
	of_node_put(np);

	bootdot_enable = true;
	pr_err("Bootdot: bootdot_phy_base=%lx, bootdot_phy_size=%lx.\n", bootdot_phy_base, bootdot_phy_size);

	return init_bootdot();
}

static const struct of_device_id bootdot_of_match[] = {
	{ .compatible = "hisilicon,bootdot" },
	{ }
};
MODULE_DEVICE_TABLE(of, bootdot_of_match);

static struct platform_driver bootdot_driver = {
	.probe	=	bootdot_probe,
	.driver	=	{
		.name = "hisilicon,bootdot",
		.of_match_table = bootdot_of_match,
	},
};
module_platform_driver(bootdot_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel Bootdot Driver");
MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_VERSION("V2.0");
