// SPDX-License-Identifier: GPL-2.0
/*
 * dt_apei kernel module
 * Copyright (c) 2020, Hisilicon Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.*
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <acpi/apei.h>

struct apei_table_params {
	acpi_physical_address phys;
	acpi_size size;
};

static void dt_apei_print_table_header(struct acpi_table_header *header)
{
	pr_info("%-4.4s %06X (v%.2d %-6.6s %-8.8s %08X %-4.4s %08X)",
		header->signature, header->length, header->revision,
		header->oem_id, header->oem_table_id, header->oem_revision,
		header->asl_compiler_id, header->asl_compiler_revision);
}

static acpi_size dt_apei_get_table_size(struct apei_table_params *table_params,
					char *signature)
{
	struct acpi_table_header *header = NULL;
	acpi_size size = 0;

	if (table_params->size < sizeof(struct acpi_table_header))
		return -ENOMEM;

	/* Map the hest table header, and extract the hest length */
	header = acpi_os_map_memory(table_params->phys,
				    sizeof(struct acpi_table_header));
	if (!header) {
		pr_err("%s: map hest table fail\n", __func__);
		return -ENOMEM;
	}

	dt_apei_print_table_header(header);
	if (strncmp(header->signature, signature,
		sizeof(header->signature)) == 0)
		size = header->length;

	acpi_os_unmap_memory(header, sizeof(struct acpi_table_header));

	return size;
}

static int __init dt_apei_parse_hest(struct apei_table_params *table_params)
{
	struct acpi_table_hest *table_hest = NULL;
	acpi_size table_size;

	table_size = dt_apei_get_table_size(table_params, ACPI_SIG_HEST);
	if ((table_size > table_params->phys) || (table_size <= 0))
		return -ENOMEM;

	/* Map the hest table, for exttract hest table */
	table_hest = acpi_os_map_memory(table_params->phys, table_size);
	if (!table_hest) {
		pr_err("%s: map hest table fail\n", __func__);
		return -ENOMEM;
	}

	acpi_dt_hest_init(table_hest);
	return 0;
}

static int dt_apei_parse_dtb(struct device_node *np,
			     struct apei_table_params *table_params)
{
	int rc;
	struct resource res;
	resource_size_t res_size;

	rc = of_address_to_resource(np, 0, &res);
	if (rc) {
		pr_err("%s: read resource address failed\n", __func__);
		return -ENODEV;
	}
	res_size = resource_size(&res);
	table_params->phys = (acpi_physical_address)res.start;
	table_params->size = (acpi_size)(uintptr_t)res_size;

	return 0;
}

static int __init do_dt_apei_init(void)
{
	int rc;
	struct device_node *np;
	struct apei_table_params table_params;

	np = of_find_compatible_node(NULL, NULL, "dt_apei, hest");
	if (np == NULL) {
		pr_err("%s:apei hest table not exist\n", __func__);
		return -ENODEV;
	}

	rc = dt_apei_parse_dtb(np, &table_params);
	if (rc != 0)
		return rc;

	/* acpi permanent mmap has been set in acpi map table */
	acpi_permanent_mmap = true;

	rc = dt_apei_parse_hest(&table_params);
	if (rc != 0)
		return rc;

	pr_info("%s: dt apei probe success\n", __func__);
	return 0;
}

static int __init dt_apei_init(void)
{
	return do_dt_apei_init();
}

subsys_initcall(dt_apei_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XiaoXun Huang <huangxiaoxun@huawei.com>");
MODULE_DESCRIPTION("HISI DT APEI DRIVER");
