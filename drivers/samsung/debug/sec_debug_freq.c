/*
 * Copyright (c) 2014-2019 Samsung Electronics Co., Ltd.
 *      http://www.samsung.com
 *
 * Samsung debugging code
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/of.h>
#include <linux/sec_debug.h>
#include <linux/debug-snapshot.h>
#include <soc/samsung/ect_parser.h>
#include <soc/samsung/exynos-dm.h>

#define MAX_FREQ_DOMAIN	20

struct table_domain {
	unsigned int main_freq;
	unsigned int sub_freq;
};

static int secdbg_dm_to_dssid[MAX_FREQ_DOMAIN];			/* index: dm-id */
#define DSS_ID(id)	(secdbg_dm_to_dssid[(id)])

static unsigned int secdbg_freq_cur[MAX_FREQ_DOMAIN];		/* index: dss-id */
#define get_cur_freq(type)	(secdbg_freq_cur[(type)])

/* Please refer to dss_freq_name[] */
static const char * const secdbg_freq_name[MAX_FREQ_DOMAIN] = {	/* index: dss-id */
	"LIT", "MID", "BIG", "INT", "MIF", "ISP", "DISP", "INTCAM", "AUD", "DSP", "DNC", "MFC", "NPU", "TNR", "G3D",
};
static const char * const secdbg_freq_lower_name[MAX_FREQ_DOMAIN] = {	/* index: dss-id */
	"lit", "mid", "big", "int", "mif", "isp", "disp", "intcam", "aud", "dsp", "dnc", "mfc", "npu", "tnr", "g3d",
};
#define get_freq_name(type)	(secdbg_freq_name[(type)])
#define get_lower_name(type)	(secdbg_freq_lower_name[(type)])

struct secdbg_skew_cache {
	unsigned int freq;
	struct table_domain *freq_table;
};

struct secdbg_skew_domain {
	struct list_head list;
	unsigned int master_dm_id;
	unsigned int slave_dm_id;
	unsigned int constraint_type;
	int master_dss_id;
	int slave_dss_id;
	int num_freq;
	const char *ect_name;
	struct secdbg_skew_cache search_cache;
	struct table_domain *freq_table;
};

static LIST_HEAD(secdbg_skew_domains);

struct secdbg_skew_ref {
	int count;	/* 0: no refs */
	struct secdbg_skew_domain *refs[MAX_FREQ_DOMAIN];
};

static struct secdbg_skew_ref *secdbg_skew_ref_table[MAX_FREQ_DOMAIN];	/* index: dss-id */

static bool secdbg_freq_initialized;

static void secdbg_print_skew_domain(struct secdbg_skew_domain *dm)
{
	struct table_domain *ft = dm->freq_table;

	pr_info("[%s]%s-%s: %d entries\n",
		dm->ect_name, get_freq_name(dm->master_dss_id),
		get_freq_name(dm->slave_dss_id), dm->num_freq);

	while (ft && ft->main_freq) {
		pr_debug("  %u %u\n", ft->main_freq, ft->sub_freq);
		ft++;
	}
}

static void secdbg_print_all_skew_domain_info(void)
{
	struct secdbg_skew_domain *dm;

	list_for_each_entry(dm, &secdbg_skew_domains, list)
		secdbg_print_skew_domain(dm);
}

static void secdbg_freq_set(int type, unsigned int freq)
{
	secdbg_freq_cur[type] = freq;
	pr_debug("%s: type: %d, freq: %u\n", __func__, type, freq);
}

static void secdbg_freq_ac_print(int type, unsigned long index,
			unsigned int main_val, unsigned int sub_val,
			unsigned int table_sub, struct secdbg_skew_domain *skew_domain)
{
	const char *freq_type = get_lower_name(type);
	const char *main_type = get_lower_name(skew_domain->master_dss_id);
	const char *sub_type = get_lower_name(skew_domain->slave_dss_id);

	/* e.g. SKEW (mif, index): big 2106 mif 1014 < 1539 @  BIG-MIF table */
	pr_auto(ASL1, "SKEW (%s, %lu): %s %u %s %u < %u @ %s-%s table\n",
			freq_type, index, main_type, main_val/1000,
			sub_type, sub_val/1000, table_sub,
			get_freq_name(skew_domain->master_dss_id),
			get_freq_name(skew_domain->slave_dss_id));

	if (IS_ENABLED(CONFIG_SEC_DEBUG_FREQ_SKEW_PANIC))
		BUG();
}

static struct table_domain *secdbg_get_suitable_freq_lb(unsigned int freq, int tsize, struct table_domain *table)
{
	struct table_domain *islot;
	struct table_domain *eslot = table + tsize;

	for (islot = table; islot < eslot; islot++) {
		pr_debug("%s: [%ld] freq: %u, table_main: %u, sub_val: %u\n",
				__func__, islot - table, freq, islot->main_freq, islot->sub_freq);

		/* table must be descending order */
		if (freq >= islot->main_freq)
			return islot;
	}

	return NULL;
}

static void secdbg_freq_main_sub(int type, unsigned long index, unsigned int freq, struct secdbg_skew_domain *domain)
{
	unsigned int master_freq;
	unsigned int slave_freq;
	struct table_domain *freq_constraint;

	master_freq = (domain->master_dss_id == type) ? freq : get_cur_freq(domain->master_dss_id);
	slave_freq = (domain->slave_dss_id == type) ? freq : get_cur_freq(domain->slave_dss_id);

	if (!master_freq || !slave_freq) {
		pr_debug("%s: no cur freq: m_%u, s_%u\n", __func__, master_freq, slave_freq);
		return;
	}

	if (master_freq == domain->search_cache.freq) {
		freq_constraint = domain->search_cache.freq_table;
		pr_debug("%s: (%d)%u cache found\n", __func__, domain->master_dss_id, master_freq);
	} else {
		freq_constraint = secdbg_get_suitable_freq_lb(master_freq, domain->num_freq, domain->freq_table);

		if (!freq_constraint) {
			pr_err("%s: no constraint: (%d)%uKhz-(%d)\n", __func__, domain->master_dss_id, master_freq, domain->slave_dss_id);
			return;
		} else {
			domain->search_cache.freq = master_freq;
			domain->search_cache.freq_table = freq_constraint;
		}
	}

	pr_debug("%s: %d: main_val: %u, table_main: %u, sub_val: %u, table_sub: %u\n",
		 __func__, type, master_freq, freq_constraint->main_freq, slave_freq, freq_constraint->sub_freq);

	if (slave_freq < freq_constraint->sub_freq)
		secdbg_freq_ac_print(type, index, master_freq, slave_freq, freq_constraint->sub_freq, domain);
}

static void secdbg_freq_judge_skew(int type, unsigned long index, unsigned int freq)
{
	int i;
	int count = secdbg_skew_ref_table[type]->count;
	struct secdbg_skew_domain *domain;

	for (i = 0; i < count; i++) {
		domain = secdbg_skew_ref_table[type]->refs[i];
		secdbg_freq_main_sub(type, index, freq, domain);
	}
}

void secdbg_freq_check(int type, unsigned long index, unsigned long freq, int en)
{
	if (!secdbg_freq_initialized) {
		pr_err_once("%s: not initialized, type(%d)\n", __func__, type);
		return;
	}

	if (type < 0 || type >= MAX_FREQ_DOMAIN) {
		pr_err("%s: type(%d) not in range\n", __func__, type);
		return;
	}

	/* skip uninterested freqs */
	if (!secdbg_skew_ref_table[type])
		return;

	pr_debug("%s: start\n", __func__);

	if (en == DSS_FLAG_OUT) {
		/* set freq. domain and target freq */
		secdbg_freq_set(type, (unsigned int)freq);
	} else if (en < 0) {
		/* error case :
		 * We cannot sure whether the frequency has been changed or not.
		 */
		secdbg_freq_set(type, 0);
		return;
	}

	/* judge skew and ac print */
	secdbg_freq_judge_skew(type, index, (unsigned int)freq);
}

static void __init secdbg_set_domain_to_ref(struct secdbg_skew_domain *domain, struct secdbg_skew_ref **skew_ref)
{
	struct secdbg_skew_ref *skref;

	if (!*skew_ref) {
		skref = kzalloc(sizeof(struct secdbg_skew_ref), GFP_KERNEL);
		if (!skref)
			return;

		skref->count = 0;
		*skew_ref = skref;
	}

	(*skew_ref)->refs[(*skew_ref)->count] = domain;
	(*skew_ref)->count++;
}

static void __init secdbg_freq_create_ref_table(void)
{
	struct secdbg_skew_domain *domain;

	list_for_each_entry(domain, &secdbg_skew_domains, list) {
		if (!domain->num_freq) {
			pr_err("%s: null table %s", __func__, domain->ect_name);
			continue;
		}

		secdbg_set_domain_to_ref(domain, &secdbg_skew_ref_table[domain->master_dss_id]);
		secdbg_set_domain_to_ref(domain, &secdbg_skew_ref_table[domain->slave_dss_id]);
	}
}

static void __init secdbg_update_dss_id(struct secdbg_skew_domain *domain)
{
	domain->master_dss_id = DSS_ID(domain->master_dm_id);
	domain->slave_dss_id = DSS_ID(domain->slave_dm_id);
}

static int __init secdbg_devfreq_init_domain(struct secdbg_skew_domain *domain,
					struct device_node *dn,
					struct device_node *child)
{
	int ret;

	ret = of_property_read_u32(dn, "dm-index", &domain->master_dm_id);
	if (ret) {
		pr_err("%s: no dm-index (%d)\n", __func__, ret);
		return ret;
	}

	ret = of_property_read_string(dn, "devfreq_domain_name", &domain->ect_name);
	if (ret) {
		pr_err("%s: no devfreq_domain_name (%d)\n", __func__, ret);
		return ret;
	}

	ret = of_property_read_u32(child, "constraint_dm_type", &domain->slave_dm_id);
	if (ret) {
		pr_err("%s: no constraint_dm_type (%d)\n", __func__, ret);
		return ret;
	}

	ret = of_property_read_u32(child, "constraint_type", &domain->constraint_type);
	if (ret) {
		pr_err("%s: no constraint_type (%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

static int __init secdbg_cpufreq_init_domain(struct secdbg_skew_domain *domain,
					struct device_node *dn)
{
	int ret;

	ret = of_property_read_u32(dn, "const-type", &domain->constraint_type);
	if (ret) {
		pr_err("%s: [%u] no const-type (%d)\n", __func__, domain->master_dm_id, ret);
		return ret;
	}

	ret = of_property_read_u32(dn, "dm-type", &domain->slave_dm_id);
	if (ret) {
		pr_err("%s: [%u] no dm-type (%d)\n", __func__, domain->master_dm_id, ret);
		return ret;
	}

	ret = of_property_read_string(dn, "ect-name", &domain->ect_name);
	if (ret) {
		pr_err("%s: [%u] no ect-name (%d)\n", __func__, domain->master_dm_id, ret);
		return ret;
	}

	return 0;
}

static void __init secdbg_free_skew_domain(struct secdbg_skew_domain *domain)
{
	kfree(domain);
}

static struct secdbg_skew_domain * __init secdbg_alloc_skew_domain(void)
{
	struct secdbg_skew_domain *domain;

	domain = kzalloc(sizeof(struct secdbg_skew_domain), GFP_KERNEL);

	return domain;
}

static bool __init __cpufreq_has_ect_constraint(struct device_node *dn)
{
	if (of_property_read_bool(dn, "guidance"))
		return true;
	else
		return false;
}

static int __init secdbg_devfreq_parse_id(struct device_node *dn)
{
	int ret;
	unsigned int dm_val, dss_val;

	ret = of_property_read_u32(dn, "dm-index", &dm_val);
	if (ret) {
		pr_err("%s: no dm-index property (%d)\n", __func__, ret);
		return ret;
	}

	ret = of_property_read_u32(dn, "ess_flag", &dss_val);
	if (ret) {
		pr_err("%s: no ess_flag property (%d)\n", __func__, ret);
		return ret;
	}

	if (dm_val >= MAX_FREQ_DOMAIN || dss_val >= MAX_FREQ_DOMAIN) {
		pr_err("%s: too big id (dm: %u, dss: %u)\n", __func__, dm_val, dss_val);
		return -1;
	}

	secdbg_dm_to_dssid[dm_val] = dss_val;
	return 0;
}

static int __init secdbg_cpufreq_parse_id(struct device_node *dn, int type)
{
	int ret;
	unsigned int val;

	ret = of_property_read_u32(dn, "dm-type", &val);
	if (ret) {
		pr_err("%s: no dm-type property (%d)\n", __func__, ret);
		return ret;
	}

	if (val >= MAX_FREQ_DOMAIN) {
		pr_err("%s: too big id (%u)\n", __func__, val);
		return -1;
	}

	secdbg_dm_to_dssid[val] = type;
	return 0;
}

static void __init secdbg_freq_dt_init(void)
{
	struct device_node *dn, *dp, *root, *child;
	struct secdbg_skew_domain *domain;
	unsigned int dm_id;
	int ret;
	int dss_id = 0;

	/* cpufreq */
	for_each_node_by_type(dn, "cpufreq-domain") {
		secdbg_cpufreq_parse_id(dn, dss_id);

		ret = of_property_read_u32(dn, "dm-type", &dm_id);
		if (ret)
			continue;

		root = of_get_child_by_name(dn, "dm-constraints");
		for_each_child_of_node(root, child) {
			if (!__cpufreq_has_ect_constraint(child))
				continue;

			domain = secdbg_alloc_skew_domain();
			if (!domain) {
				pr_err("%s: failed to allocate skew domain[%s]\n", __func__, child->name);
				continue;
			}

			//domain->dn = dn;
			domain->master_dm_id = dm_id;
			ret = secdbg_cpufreq_init_domain(domain, child);
			if (ret) {
				pr_err("%s: failed to initialize skew domain[%s]\n", __func__, child->name);
				secdbg_free_skew_domain(domain);
				continue;
			}

			list_add_tail(&domain->list, &secdbg_skew_domains);
			//secdbg_print_domain_info(domain);
		}
		of_node_put(root);
		dss_id++;
	}

	/* devfreq */
	dp = of_find_compatible_node(NULL, NULL, "samsung,exynos-devfreq-root");
	if (!dp) {
		pr_notice("%s: no devfreq dt\n", __func__);
		goto out;
	}

	for_each_child_of_node(dp, dn) {
		if (!of_device_is_compatible(dn, "samsung,exynos-devfreq"))
			continue;

		secdbg_devfreq_parse_id(dn);

		root = of_get_child_by_name(dn, "skew");
		if (!root)
			continue;

		for_each_available_child_of_node(root, child) {
			domain = secdbg_alloc_skew_domain();
			if (!domain) {
				pr_err("%s: failed to allocate skew domain[%s]\n", __func__, child->name);
				continue;
			}

			//domain->dn = dn;
			domain->master_dm_id = dm_id;

			ret = secdbg_devfreq_init_domain(domain, dn, child);
			if (ret) {
				pr_err("%s: failed to initialize skew domain[%s]\n", __func__, child->name);
				secdbg_free_skew_domain(domain);
				continue;
			}

			list_add_tail(&domain->list, &secdbg_skew_domains);
			//secdbg_print_domain_info(domain);
		}

		of_node_put(root);
	}

	of_node_put(dp);

out:
	list_for_each_entry(domain, &secdbg_skew_domains, list)
		secdbg_update_dss_id(domain);
}

static int __init secdbg_freq_mini_table(struct ect_minlock_domain *ect_domain, struct table_domain table[])
{
	unsigned int i, j, k;

	for (i = 0, j = 0; j < ect_domain->num_of_level - 1; j++) {
		pr_debug("secdbg_freq: %s: i:%d, %u %u\n", ect_domain->domain_name, i, ect_domain->level[j].main_frequencies, ect_domain->level[j].sub_frequencies);
		if (ect_domain->level[j].sub_frequencies != ect_domain->level[j+1].sub_frequencies) {
			table[i].main_freq = ect_domain->level[j].main_frequencies;
			table[i].sub_freq = ect_domain->level[j].sub_frequencies;
			i++;
		}
	}
	pr_debug("secdbg_freq: %s: i:%d, %u %u\n", ect_domain->domain_name, i, ect_domain->level[j].main_frequencies, ect_domain->level[j].sub_frequencies);
	table[i].main_freq = ect_domain->level[ect_domain->num_of_level - 1].main_frequencies;
	table[i].sub_freq = ect_domain->level[ect_domain->num_of_level - 1].sub_frequencies;
	i++;

	for (k = 0; k < i; k++)
		pr_info("secdbg: %s: %u %u\n", ect_domain->domain_name, table[k].main_freq, table[k].sub_freq);

	return i;
}

static void __init secdbg_freq_gen_table(struct secdbg_skew_domain *skew_domain, struct ect_minlock_domain *ect_domain)
{
	skew_domain->freq_table = kcalloc(ect_domain->num_of_level + 1,
					  sizeof(struct table_domain),
					  GFP_KERNEL);
	if (!skew_domain->freq_table) {
		pr_err("%s: [%u] failed to alloc table\n", __func__, skew_domain->master_dm_id);
		return;
	}

	skew_domain->num_freq = secdbg_freq_mini_table(ect_domain, skew_domain->freq_table);
}

static int __init secdbg_init_constraint_ect(struct secdbg_skew_domain *skew_domain)
{
	void *min_block;
	struct ect_minlock_domain *ect_domain;

	/* get ect domain1, domain2 */
	min_block = ect_get_block(BLOCK_MINLOCK);
	if (!min_block) {
		pr_err("%s: no BLOCK_MINLOCK\n", __func__);
		return -ENODEV;
	}

	/* Actually, ect_minlock_get_domain() doesn't change a domain_name. */
	ect_domain = ect_minlock_get_domain(min_block, (char *)skew_domain->ect_name);
	if (!ect_domain) {
		pr_err("%s: no ect domain for %s\n", __func__, skew_domain->ect_name);
		return -ENODEV;
	}

	secdbg_freq_gen_table(skew_domain, ect_domain);

	return 0;
}

static void __init secdbg_freq_ect_data_init(void)
{
	struct secdbg_skew_domain *domain, *tmp;

	list_for_each_entry_safe(domain, tmp, &secdbg_skew_domains, list) {
		if (secdbg_init_constraint_ect(domain)) {
			/* we don't remove domain failed for debug */
		}
	}
}

int secdbg_freq_init(void)
{
	secdbg_freq_dt_init();

	secdbg_freq_ect_data_init();

	secdbg_freq_create_ref_table();

	secdbg_freq_initialized = true;

	secdbg_print_all_skew_domain_info();

	pr_info("%s: initialized\n", __func__);

	return 0;
}
