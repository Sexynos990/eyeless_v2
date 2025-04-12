/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PULNICE_H_
#define _PULNICE_H_

#include <linux/cpufreq.h>
#include <linux/version.h>

/* Version detection */
#define PULNICE_4_19_325 (LINUX_VERSION_CODE == KERNEL_VERSION(4,19,325))
#define PULNICE_5_10_PLUS (LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0))

/* Backported util for <5.10 */
#if !PULNICE_5_10_PLUS
static inline unsigned long pulnice_cpu_util(int cpu)
{
    struct rq *rq = cpu_rq(cpu);
    #if PULNICE_4_19_325
    return (rq->cfs.avg.util_avg * SCHED_CAPACITY_SCALE) >> SCHED_CAPACITY_SHIFT;
    #else
    return (rq->avg.util_avg * SCHED_CAPACITY_SCALE) >> SCHED_CAPACITY_SHIFT;
    #endif
}
#else
#define pulnice_cpu_util sched_cpu_util
#endif

/* Thermal pressure backport */
#ifndef cpufreq_get_thermal_limit
static inline unsigned int cpufreq_get_thermal_limit(int cpu) { return 0; }
#endif

#endif /* _PULNICE_H_ */