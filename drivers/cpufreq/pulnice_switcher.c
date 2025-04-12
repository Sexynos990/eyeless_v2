/*
 * pulnice_switcher.c - Safely switch to pulnice governor using sysfs I/O
 * (Kernel-space equivalent of: echo pulnice > /sys/.../scaling_governor)
 */

#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/module.h>

#define MAX_RETRIES 10
#define RETRY_DELAY_MS 3000

static struct delayed_work switcher_work;
static unsigned int retry_count;

static bool try_switch_cpu(unsigned int cpu)
{
    struct file *filp;
    loff_t pos = 0;
    char path[128], current_gov[16];
    const char *target_gov = "pulnice";
    ssize_t len;
    int ret;

    // Try both possible sysfs paths
    snprintf(path, sizeof(path),
        "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor", cpu);
    if (strlen(path) >= sizeof(path))
        return false;

    filp = filp_open(path, O_RDWR | O_LARGEFILE, 0);
    if (IS_ERR(filp)) {
        snprintf(path, sizeof(path),
            "/sys/devices/system/cpu/cpufreq/policy%d/scaling_governor", cpu);
        filp = filp_open(path, O_RDWR | O_LARGEFILE, 0);
    }

    if (IS_ERR(filp))
        return false;

    // Read current governor
    len = kernel_read(filp, current_gov, sizeof(current_gov) - 1, &pos);
    if (len <= 0) {
        filp_close(filp, NULL);
        return false;
    }
    current_gov[len] = '\0';

    // Skip if already using pulnice
    if (strstr(current_gov, target_gov)) {
        filp_close(filp, NULL);
        return true;
    }

    // Write new governor
    pos = 0;
    ret = kernel_write(filp, target_gov, strlen(target_gov), &pos);
    filp_close(filp, NULL);

    return (ret == strlen(target_gov));
}

static void switcher_work_fn(struct work_struct *work)
{
    unsigned int cpu;
    bool success = true;

    for_each_online_cpu(cpu) {
        if (!try_switch_cpu(cpu)) {
            pr_err("CPU%d: Failed to switch governor\n", cpu);
            success = false;
        }
    }

    if (!success && retry_count++ < MAX_RETRIES) {
        pr_info("Retrying in %dms (%u/%u)\n",
               RETRY_DELAY_MS, retry_count, MAX_RETRIES);
        schedule_delayed_work(&switcher_work,
                            msecs_to_jiffies(RETRY_DELAY_MS));
    } else if (!success) {
        pr_err("Failed after %d attempts\n", MAX_RETRIES);
    } else {
        pr_info("Successfully switched all CPUs to pulnice\n");
    }
}

static int __init switcher_init(void)
{
    INIT_DELAYED_WORK(&switcher_work, switcher_work_fn);
    schedule_delayed_work(&switcher_work, msecs_to_jiffies(15000)); // Wait 15s
    return 0;
}

module_init(switcher_init);
MODULE_LICENSE("GPL");