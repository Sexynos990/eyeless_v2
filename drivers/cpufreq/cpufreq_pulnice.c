/*
 * CPU Frequency Governor: Pulnice v3.1
 * Author: Boyan Spassov
 * License: GPL v2
 * Kernel 4.19.325 compatible version
 */

#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/thermal.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/rwsem.h>

/* Tunable parameters with defaults */
#define PULNICE_DEF_UTIL_HIGH      70
#define PULNICE_DEF_UTIL_MID       50
#define PULNICE_DEF_UTIL_LOW       30
#define PULNICE_DEF_HYSTERESIS     5
#define PULNICE_DEF_FREQ_HYST      100000 /* 100 MHz */
#define PULNICE_DEF_RATE_LIMIT_US  10000  /* 10ms */

struct pulnice_policy {
    struct cpufreq_policy *policy;
    
    /* Tunables */
    unsigned int util_high;
    unsigned int util_mid;
    unsigned int util_low;
    unsigned int hysteresis;
    unsigned int freq_hysteresis;
    unsigned int rate_limit_us;
    
    /* Frequency management */
    unsigned int passive_freq;
    unsigned int boost_freq;
    unsigned int last_freq;
    u64 last_update;
    
    /* Thermal protection */
    unsigned int thermal_limit;
    
    /* Synchronization */
    struct rw_semaphore rwsem;
    
    /* Sysfs */
    struct kobject kobj;
};

/* Forward declarations for sysfs functions */
static ssize_t pulnice_show(struct kobject *kobj, struct attribute *attr, char *buf);
static ssize_t pulnice_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t count);

/* Sysfs show/store functions */
#define show_one(file, var)                                    \
static ssize_t show_##var(struct kobject *kobj,                \
    struct attribute *attr, char *buf)                         \
{                                                              \
    struct pulnice_policy *pn = container_of(kobj,             \
        struct pulnice_policy, kobj);                          \
    return sprintf(buf, "%u\n", pn->var);                      \
}

#define store_one(file, var, min, max)                        \
static ssize_t store_##var(struct kobject *kobj,              \
    struct attribute *attr, const char *buf, size_t count)    \
{                                                             \
    struct pulnice_policy *pn = container_of(kobj,             \
        struct pulnice_policy, kobj);                         \
    unsigned int val;                                         \
    int ret;                                                  \
                                                              \
    ret = sscanf(buf, "%u", &val);                            \
    if (ret != 1)                                             \
        return -EINVAL;                                       \
                                                              \
    if (val < min || val > max)                               \
        return -EINVAL;                                       \
                                                              \
    down_write(&pn->rwsem);                                   \
    pn->var = val;                                            \
    up_write(&pn->rwsem);                                     \
                                                              \
    return count;                                             \
}

show_one(util_high, util_high);
store_one(util_high, util_high, 0, 100);
show_one(util_mid, util_mid);
store_one(util_mid, util_mid, 0, 100);
show_one(util_low, util_low);
store_one(util_low, util_low, 0, 100);
show_one(hysteresis, hysteresis);
store_one(hysteresis, hysteresis, 0, 20);
show_one(freq_hysteresis, freq_hysteresis);
store_one(freq_hysteresis, freq_hysteresis, 0, INT_MAX);
show_one(rate_limit_us, rate_limit_us);
store_one(rate_limit_us, rate_limit_us, 0, INT_MAX);

static ssize_t show_passive_freq(struct kobject *kobj,
    struct attribute *attr, char *buf)
{
    struct pulnice_policy *pn = container_of(kobj,
        struct pulnice_policy, kobj);
    return sprintf(buf, "%u\n", pn->passive_freq);
}

static ssize_t store_passive_freq(struct kobject *kobj,
    struct attribute *attr, const char *buf, size_t count)
{
    struct pulnice_policy *pn = container_of(kobj,
        struct pulnice_policy, kobj);
    unsigned int val;
    int ret;

    ret = sscanf(buf, "%u", &val);
    if (ret != 1)
        return -EINVAL;

    down_write(&pn->rwsem);
    pn->passive_freq = clamp_val(val, pn->policy->min, pn->policy->max);
    up_write(&pn->rwsem);

    return count;
}

static ssize_t show_boost_freq(struct kobject *kobj,
    struct attribute *attr, char *buf)
{
    struct pulnice_policy *pn = container_of(kobj,
        struct pulnice_policy, kobj);
    return sprintf(buf, "%u\n", pn->boost_freq);
}

static ssize_t store_boost_freq(struct kobject *kobj,
    struct attribute *attr, const char *buf, size_t count)
{
    struct pulnice_policy *pn = container_of(kobj,
        struct pulnice_policy, kobj);
    unsigned int val;
    int ret;

    ret = sscanf(buf, "%u", &val);
    if (ret != 1)
        return -EINVAL;

    down_write(&pn->rwsem);
    pn->boost_freq = clamp_val(val, pn->policy->min, pn->policy->max);
    up_write(&pn->rwsem);

    return count;
}

/* Sysfs attribute definitions */
static struct attribute util_high_attr = {
    .name = "util_high",
    .mode = 0644,
};

static struct attribute util_mid_attr = {
    .name = "util_mid",
    .mode = 0644,
};

static struct attribute util_low_attr = {
    .name = "util_low",
    .mode = 0644,
};

static struct attribute hysteresis_attr = {
    .name = "hysteresis",
    .mode = 0644,
};

static struct attribute freq_hysteresis_attr = {
    .name = "freq_hysteresis",
    .mode = 0644,
};

static struct attribute rate_limit_us_attr = {
    .name = "rate_limit_us",
    .mode = 0644,
};

static struct attribute passive_freq_attr = {
    .name = "passive_freq",
    .mode = 0644,
};

static struct attribute boost_freq_attr = {
    .name = "boost_freq",
    .mode = 0644,
};

static struct attribute *pulnice_attrs[] = {
    &util_high_attr,
    &util_mid_attr,
    &util_low_attr,
    &hysteresis_attr,
    &freq_hysteresis_attr,
    &rate_limit_us_attr,
    &passive_freq_attr,
    &boost_freq_attr,
    NULL
};

static const struct sysfs_ops pulnice_sysfs_ops = {
    .show = pulnice_show,
    .store = pulnice_store,
};

static struct kobj_type pulnice_ktype = {
    .sysfs_ops = &pulnice_sysfs_ops,
    .default_attrs = pulnice_attrs,
};

/* Core governor implementation */
static unsigned int pulnice_get_util(unsigned int cpu)
{
    u64 idle_time, total_time;
    unsigned int util;
    
    idle_time = get_cpu_idle_time(cpu, &total_time, 1);
    if (unlikely(total_time == 0))
        return 0;
    
    util = 100 - div64_u64(100 * idle_time, total_time);
    return util;
}

static unsigned int pulnice_get_thermal_limit(struct cpufreq_policy *policy)
{
    #ifdef CONFIG_CPU_THERMAL
    return 0; /* Simplified for 4.19.325 */
    #else
    return 0;
    #endif
}

static unsigned int pulnice_calc_target(struct pulnice_policy *pn, unsigned int util)
{
    struct cpufreq_policy *policy = pn->policy;
    unsigned int new_freq, max_freq = pn->thermal_limit ? 
        min(policy->max, pn->thermal_limit) : policy->max;

    down_read(&pn->rwsem);
    if (util >= pn->util_high + (pn->last_freq < max_freq ? pn->hysteresis : 0))
        new_freq = max_freq;
    else if (util >= pn->util_mid + (pn->last_freq < pn->boost_freq ? pn->hysteresis : 0))
        new_freq = pn->boost_freq;
    else if (util >= pn->util_low + (pn->last_freq < pn->passive_freq ? pn->hysteresis : 0))
        new_freq = pn->passive_freq;
    else
        new_freq = policy->min;

    if (abs((int)new_freq - (int)pn->last_freq) < pn->freq_hysteresis)
        new_freq = pn->last_freq;

    new_freq = clamp_val(new_freq, policy->min, max_freq);
    up_read(&pn->rwsem);

    return new_freq;
}

static void pulnice_update(struct pulnice_policy *pn)
{
    struct cpufreq_policy *policy = pn->policy;
    u64 now = ktime_get_ns();
    unsigned int util, new_freq;
    
    if (now < pn->last_update + pn->rate_limit_us * NSEC_PER_USEC)
        return;

    util = pulnice_get_util(policy->cpu);
    new_freq = pulnice_calc_target(pn, util);

    if (new_freq != pn->last_freq) {
        pn->last_update = now;
        pn->last_freq = new_freq;
        __cpufreq_driver_target(policy, new_freq, CPUFREQ_RELATION_C);
    }
}

/* Governor hooks */
static int pulnice_policy_init(struct cpufreq_policy *policy)
{
    struct pulnice_policy *pn;
    unsigned int i, valid_freqs = 0;
    int ret;

    pn = kzalloc(sizeof(*pn), GFP_KERNEL);
    if (!pn)
        return -ENOMEM;

    init_rwsem(&pn->rwsem);
    pn->policy = policy;

    /* Initialize frequency table */
    for (i = 0; policy->freq_table[i].frequency != CPUFREQ_TABLE_END; i++)
        if (policy->freq_table[i].frequency != CPUFREQ_ENTRY_INVALID)
            valid_freqs++;

    /* Set default parameters */
    down_write(&pn->rwsem);
    pn->passive_freq = policy->freq_table[valid_freqs/2].frequency;
    pn->boost_freq = policy->freq_table[(valid_freqs * 3)/4].frequency;
    pn->util_high = PULNICE_DEF_UTIL_HIGH;
    pn->util_mid = PULNICE_DEF_UTIL_MID;
    pn->util_low = PULNICE_DEF_UTIL_LOW;
    pn->hysteresis = PULNICE_DEF_HYSTERESIS;
    pn->freq_hysteresis = PULNICE_DEF_FREQ_HYST;
    pn->rate_limit_us = PULNICE_DEF_RATE_LIMIT_US;
    pn->thermal_limit = pulnice_get_thermal_limit(policy);
    up_write(&pn->rwsem);

    policy->governor_data = pn;

    /* Initialize sysfs */
    ret = kobject_init_and_add(&pn->kobj, &pulnice_ktype, 
        &policy->kobj, "pulnice");
    if (ret) {
        kfree(pn);
        return ret;
    }

    return 0;
}

static void pulnice_policy_exit(struct cpufreq_policy *policy)
{
    struct pulnice_policy *pn = policy->governor_data;
    
    if (pn) {
        kobject_put(&pn->kobj);
        kfree(pn);
        policy->governor_data = NULL;
    }
}

static int pulnice_policy_start(struct cpufreq_policy *policy)
{
    struct pulnice_policy *pn = policy->governor_data;
    if (!pn)
        return -EINVAL;

    pn->last_freq = policy->cur;
    pn->last_update = ktime_get_ns();
    return 0;
}

static void pulnice_policy_limits(struct cpufreq_policy *policy)
{
    struct pulnice_policy *pn = policy->governor_data;
    if (pn) {
        down_write(&pn->rwsem);
        pn->thermal_limit = pulnice_get_thermal_limit(policy);
        up_write(&pn->rwsem);
        pulnice_update(pn);
    }
}

/* Sysfs show/store dispatcher */
static ssize_t pulnice_show(struct kobject *kobj, struct attribute *attr,
                  char *buf)
{
    if (attr == &util_high_attr)
        return show_util_high(kobj, attr, buf);
    if (attr == &util_mid_attr)
        return show_util_mid(kobj, attr, buf);
    if (attr == &util_low_attr)
        return show_util_low(kobj, attr, buf);
    if (attr == &hysteresis_attr)
        return show_hysteresis(kobj, attr, buf);
    if (attr == &freq_hysteresis_attr)
        return show_freq_hysteresis(kobj, attr, buf);
    if (attr == &rate_limit_us_attr)
        return show_rate_limit_us(kobj, attr, buf);
    if (attr == &passive_freq_attr)
        return show_passive_freq(kobj, attr, buf);
    if (attr == &boost_freq_attr)
        return show_boost_freq(kobj, attr, buf);
    return 0;
}

static ssize_t pulnice_store(struct kobject *kobj, struct attribute *attr,
                   const char *buf, size_t count)
{
    if (attr == &util_high_attr)
        return store_util_high(kobj, attr, buf, count);
    if (attr == &util_mid_attr)
        return store_util_mid(kobj, attr, buf, count);
    if (attr == &util_low_attr)
        return store_util_low(kobj, attr, buf, count);
    if (attr == &hysteresis_attr)
        return store_hysteresis(kobj, attr, buf, count);
    if (attr == &freq_hysteresis_attr)
        return store_freq_hysteresis(kobj, attr, buf, count);
    if (attr == &rate_limit_us_attr)
        return store_rate_limit_us(kobj, attr, buf, count);
    if (attr == &passive_freq_attr)
        return store_passive_freq(kobj, attr, buf, count);
    if (attr == &boost_freq_attr)
        return store_boost_freq(kobj, attr, buf, count);
    return 0;
}

static struct cpufreq_governor cpufreq_gov_pulnice = {
    .name = "pulnice",
    .init = pulnice_policy_init,
    .exit = pulnice_policy_exit,
    .start = pulnice_policy_start,
    .limits = pulnice_policy_limits,
    .owner = THIS_MODULE,
};

/* Built-in/module initialization */
#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_PULNICE
struct cpufreq_governor *cpufreq_default_governor(void)
{
    return &cpufreq_gov_pulnice;
}
#endif

static int __init pulnice_mod_init(void)
{
    return cpufreq_register_governor(&cpufreq_gov_pulnice);
}

#ifdef CONFIG_CPU_FREQ_GOV_PULNICE_MODULE
module_init(pulnice_mod_init);
#else
fs_initcall(pulnice_mod_init);
#endif

MODULE_AUTHOR("Boyan Spassov");
MODULE_DESCRIPTION("Pulnice v3.1 CPU Frequency Governor");
MODULE_LICENSE("GPL");