#include <linux/acpi.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/ascend_smmu.h>
#include <linux/iommu.h>
#include <generated/uapi/linux/version.h>
#include <linux/arm-smmu.h>

static int __smmu_set_mpam(struct device *dev, void *data)
{
	return iommu_dev_set_config(dev, ARM_SMMU_MPAM, data);
}
static int __smmu_get_mpam(struct device *dev, void *data)
{
	return iommu_dev_get_config(dev, ARM_SMMU_MPAM, data);
}

#define ASCEND_MPAM_DEVICE_NAME "ascend_mpam"

struct ascend_mpam_device {
	struct device_node *np;
	struct platform_device *pdev;
	bool include_all_child;
	struct list_head entry;
};

static LIST_HEAD(amdev_list);
static struct mutex ascend_mpam_mutex;

static int ascend_mpam_of_try_probe_pdev(struct ascend_mpam_device *amdev)
{
	const char *parent = NULL;
	struct device_node *np;

	if (amdev->pdev)
		return 0;

	if (of_property_read_string(amdev->np, "parent", &parent))
		return -EINVAL;

	np = of_find_node_by_name(NULL, parent);
	if (!np)
		return -EINVAL;

	amdev->pdev = of_find_device_by_node(np);
	if (!amdev->pdev) {
		pr_warn("parent device %s not ready!\n", parent);
		return -ENODEV;
	}

	return 0;
}

static bool child_name_match(struct ascend_mpam_device *amdev, struct device *dev)
{
	const char *name;
	struct property *p;

	of_property_for_each_string(amdev->np, "child-names", p, name) {
		if (strcmp(name, dev->of_node->name) == 0)
			return true;
	}

	return false;
}

struct ascend_mpam_data {
	struct ascend_mpam_device *amdev;
	int (*fn)(struct device *, void *);
	void *data;
};

static int child_dev_fn(struct device *dev, void *data)
{
	struct ascend_mpam_data *amdata = data;
	struct ascend_mpam_device *amdev = amdata->amdev;

	if (child_name_match(amdev, dev) && amdata->fn)
		return amdata->fn(dev, amdata->data);

	return 0;
}

static int ascend_mpam_for_each_child(struct ascend_mpam_device *amdev,
		void *data, int (*fn)(struct device *, void *))
{
	int ret;
	struct ascend_mpam_data amdata = {0};

	if (!amdev || !amdev->np) {
		return -EINVAL;
	}

	if (!amdev->pdev) {
		ret = ascend_mpam_of_try_probe_pdev(amdev);
		if (ret)
			return ret;
	}

	if (amdev->include_all_child) {
		device_for_each_child(&amdev->pdev->dev, data, fn);
	} else {
		amdata.amdev = amdev;
		amdata.fn = fn;
		amdata.data = data;
		device_for_each_child(&amdev->pdev->dev, &amdata, child_dev_fn);
	}

	return 0;
}

static int ascend_mpam_for_each_device(void *data, int (*fn)(struct device *, void *))
{
	int ret;
	struct ascend_mpam_device *amdev;

	mutex_lock(&ascend_mpam_mutex);
	list_for_each_entry(amdev, &amdev_list, entry) {
		ret = ascend_mpam_for_each_child(amdev, data, fn);
		if (ret)
			break;
	}
	mutex_unlock(&ascend_mpam_mutex);

	return 0;
}

static int ascend_mpam_of_add_device(struct device_node *np)
{
	struct ascend_mpam_device *amdev;
	amdev = kzalloc(sizeof(struct ascend_mpam_device), GFP_KERNEL);
	if (!amdev)
		return -ENOMEM;

	amdev->np = np;
	amdev->include_all_child = of_property_read_bool(np, "include-all-child");
	ascend_mpam_of_try_probe_pdev(amdev);
	list_add(&amdev->entry, &amdev_list);
	return 0;
}

static const struct of_device_id ascend_mpam_of_match[] = {
	{ .compatible = "hisilicon,ascend_mpam" },
	{ }
};
MODULE_DEVICE_TABLE(of, ascend_mpam_of_match);

static int ascend_mpam_device_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct device *dev = &pdev->dev;
	struct device_node *child;

	if (!acpi_disabled || !dev->of_node)
		return -EINVAL;

	if (!of_match_node(ascend_mpam_of_match, pdev->dev.of_node))
		return -EINVAL;

	for_each_available_child_of_node(dev->of_node, child) {
		ret = ascend_mpam_of_add_device(child);
		if (ret)
			pr_err("probe child node %s failed ret:%d\n",
					child->name, ret);
	}

	mutex_init(&ascend_mpam_mutex);

	return ret;
}

static int ascend_mpam_device_remove(struct platform_device *pdev)
{
	struct ascend_mpam_device *amdev;

	list_for_each_entry(amdev, &amdev_list, entry) {
		list_del(&amdev->entry);
		kfree(amdev);
	}

	return 0;
}

int ascend_smmu_set_mpam(int pasid, int partid, int pmg, int s1mpam)
{
	int ret;
	struct arm_smmu_mpam mpam, old_mpam;

	old_mpam.flags = ARM_SMMU_DEV_GET_MPAM;
	old_mpam.pasid = pasid;
	ret = ascend_mpam_for_each_device(&old_mpam, __smmu_get_mpam);
	if (ret)
		return ret;

	mpam.pasid = pasid;
	mpam.partid = partid;
	mpam.pmg = pmg;
	mpam.s1mpam = s1mpam;
	mpam.flags = ARM_SMMU_DEV_SET_MPAM;
	ret = ascend_mpam_for_each_device(&mpam, __smmu_set_mpam);
	if (ret)
		goto rollback;

	return 0;

rollback:
	ascend_mpam_for_each_device(&old_mpam, __smmu_set_mpam);
	return ret;
}
EXPORT_SYMBOL_GPL(ascend_smmu_set_mpam);

int ascend_smmu_get_mpam(int pasid, int *partid, int *pmg, int *s1mpam)
{
	int ret;
	struct arm_smmu_mpam mpam = {
		.pasid = pasid,
		.flags = ARM_SMMU_DEV_GET_MPAM,
	};

	ret = ascend_mpam_for_each_device(&mpam, __smmu_get_mpam);
	if (ret)
		return ret;

	*partid = mpam.partid;
	*pmg = mpam.pmg;
	*s1mpam = mpam.s1mpam;

	return 0;
}
EXPORT_SYMBOL_GPL(ascend_smmu_get_mpam);

int ascend_smmu_set_user_mpam_en(int user_mpam_en)
{
	int ret;
	struct arm_smmu_mpam mpam, old_mpam;

	old_mpam.flags = ARM_SMMU_DEV_GET_USER_MPAM_EN;
	ret = ascend_mpam_for_each_device(&old_mpam, __smmu_get_mpam);
	if (ret)
		return ret;

	mpam.user_mpam_en = user_mpam_en;
	mpam.flags = ARM_SMMU_DEV_SET_USER_MPAM_EN;
	ret = ascend_mpam_for_each_device(&mpam, __smmu_set_mpam);
	if (ret)
		goto rollback;

	return 0;

rollback:
	ascend_mpam_for_each_device(&old_mpam, __smmu_set_mpam);
	return ret;
}
EXPORT_SYMBOL_GPL(ascend_smmu_set_user_mpam_en);

int ascend_smmu_get_user_mpam_en(int *user_mpam_en)
{
	int ret;
	struct arm_smmu_mpam mpam = {
		.flags = ARM_SMMU_DEV_GET_USER_MPAM_EN,
	};

	ret = ascend_mpam_for_each_device(&mpam, __smmu_get_mpam);
	if (ret)
		return ret;

	*user_mpam_en = mpam.user_mpam_en;
	return 0;
}
EXPORT_SYMBOL_GPL(ascend_smmu_get_user_mpam_en);

static struct platform_driver ascend_mpam_driver = {
	.probe		= ascend_mpam_device_probe,
	.remove		= ascend_mpam_device_remove,
	.driver		= {
		.name = ASCEND_MPAM_DEVICE_NAME,
		.of_match_table = ascend_mpam_of_match,
	},
};

module_platform_driver(ascend_mpam_driver);
MODULE_DESCRIPTION("Hisilicon ASCEND MPAM driver");
MODULE_LICENSE("GPL v2");
