/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dt_apei.h - APEI notifier Interface
 */

#ifndef ACPI_DT_APEI_H
#define ACPI_DT_APEI_H

#include <linux/notifier.h>

#define DT_APEI_ENABLED (1)
#define DT_APEI_DISABLED (0)

extern bool enable_acpi_dt_apei;
extern bool dt_apei_disable;

#ifdef CONFIG_ACPI_DT_APEI
int register_dt_apei_notifier(struct notifier_block *nb);
void unregister_dt_apei_notifier(struct notifier_block *nb);
#else
static inline int register_dt_apei_notifier(struct notifier_block *nb)
{
	return -EINVAL;
}

static inline void unregister_dt_apei_notifier(struct notifier_block *nb)
{
	return;
}
#endif
#endif
