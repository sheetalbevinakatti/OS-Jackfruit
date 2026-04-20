/*
 * monitor.c - Multi-Container Memory Monitor (Linux Kernel Module)
 *
 * Task 4 implementation:
 *   TODO 1: monitored_entry struct with list_head
 *   TODO 2: global list + mutex
 *   TODO 3: timer_callback - RSS check, soft warn, hard kill
 *   TODO 4: ioctl REGISTER - allocate and insert entry
 *   TODO 5: ioctl UNREGISTER - find and remove entry
 *   TODO 6: monitor_exit - free all entries
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME        "container_monitor"
#define CHECK_INTERVAL_SEC 1

/* ---------------------------------------------------------------
 * TODO 1: Linked-list node struct
 *
 * Tracks one container process. soft_warned ensures we only emit
 * the soft-limit warning once per container (not every second).
 * --------------------------------------------------------------- */
struct monitored_entry {
    pid_t          pid;
    char           container_id[MONITOR_NAME_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            soft_warned;     /* 1 after first soft-limit warning */
    struct list_head list;          /* kernel linked-list linkage */
};

/* ---------------------------------------------------------------
 * TODO 2: Global list and mutex
 *
 * We use a mutex (not a spinlock) because:
 *   - The timer callback runs in softirq context but we use
 *     mutex_trylock() there to avoid sleeping in interrupt context.
 *   - The ioctl paths run in process context and can sleep, so
 *     a full mutex_lock() is safe and avoids priority inversion.
 *   - kmalloc(GFP_KERNEL) in the register path can sleep, which
 *     is only safe with a mutex, not a spinlock.
 * --------------------------------------------------------------- */
static LIST_HEAD(monitored_list);
static DEFINE_MUTEX(list_lock);

/* --- Provided: internal device / timer state --- */
static struct timer_list monitor_timer;
static dev_t             dev_num;
static struct cdev       c_dev;
static struct class     *cl;

/* ---------------------------------------------------------------
 * Provided: RSS Helper
 * Returns RSS in bytes for the given PID, or -1 if gone.
 * --------------------------------------------------------------- */
static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);
    return rss_pages * PAGE_SIZE;
}

/* ---------------------------------------------------------------
 * Provided: soft-limit warning helper
 * --------------------------------------------------------------- */
static void log_soft_limit_event(const char *container_id,
                                 pid_t pid,
                                 unsigned long limit_bytes,
                                 long rss_bytes)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d"
           " rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ---------------------------------------------------------------
 * Provided: hard-limit kill helper
 * --------------------------------------------------------------- */
static void kill_process(const char *container_id,
                         pid_t pid,
                         unsigned long limit_bytes,
                         long rss_bytes)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        send_sig(SIGKILL, task, 1);
    rcu_read_unlock();

    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d"
           " rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

/* ---------------------------------------------------------------
 * TODO 3: Timer callback — fires every CHECK_INTERVAL_SEC seconds
 *
 * Walk the monitored list and for each entry:
 *   1. Get current RSS. If process is gone, remove the entry.
 *   2. If RSS > hard limit: kill the process and remove the entry.
 *   3. If RSS > soft limit and not yet warned: log warning, set flag.
 *
 * We use mutex_trylock() here because the timer runs in softirq
 * context. If the lock is held by an ioctl, we skip this tick
 * and try again next second — safe because limits are soft deadlines.
 *
 * list_for_each_entry_safe() lets us delete the current entry
 * without corrupting the iterator (it saves the next pointer first).
 * --------------------------------------------------------------- */
static void timer_callback(struct timer_list *t)
{
    struct monitored_entry *entry, *tmp;

    if (!mutex_trylock(&list_lock))
        goto reschedule;

    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
        long rss = get_rss_bytes(entry->pid);

        /* Process no longer exists — clean up the entry */
        if (rss < 0) {
            printk(KERN_INFO
                   "[container_monitor] container=%s pid=%d exited,"
                   " removing from monitor\n",
                   entry->container_id, entry->pid);
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        /* Hard limit exceeded — kill and remove */
        if ((unsigned long)rss > entry->hard_limit_bytes) {
            kill_process(entry->container_id, entry->pid,
                         entry->hard_limit_bytes, rss);
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        /* Soft limit exceeded — warn once */
        if ((unsigned long)rss > entry->soft_limit_bytes &&
            !entry->soft_warned) {
            log_soft_limit_event(entry->container_id, entry->pid,
                                 entry->soft_limit_bytes, rss);
            entry->soft_warned = 1;
        }
    }

    mutex_unlock(&list_lock);

reschedule:
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

/* ---------------------------------------------------------------
 * IOCTL Handler
 * --------------------------------------------------------------- */
static long monitor_ioctl(struct file *f, unsigned int cmd,
                          unsigned long arg)
{
    struct monitor_request req;

    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;

    if (copy_from_user(&req, (struct monitor_request __user *)arg,
                       sizeof(req)))
        return -EFAULT;

    /* ---------------------------------------------------------------
     * TODO 4: REGISTER — allocate and insert a new entry
     * --------------------------------------------------------------- */
    if (cmd == MONITOR_REGISTER) {
        struct monitored_entry *entry;

        printk(KERN_INFO
               "[container_monitor] Registering container=%s pid=%d"
               " soft=%lu hard=%lu\n",
               req.container_id, req.pid,
               req.soft_limit_bytes, req.hard_limit_bytes);

        /* Validate limits */
        if (req.soft_limit_bytes > req.hard_limit_bytes) {
            printk(KERN_WARNING
                   "[container_monitor] Invalid limits for %s:"
                   " soft > hard\n", req.container_id);
            return -EINVAL;
        }

        /* Allocate the node — GFP_KERNEL is safe in process context */
        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            return -ENOMEM;

        /* Fill in the node */
        entry->pid              = req.pid;
        entry->soft_limit_bytes = req.soft_limit_bytes;
        entry->hard_limit_bytes = req.hard_limit_bytes;
        entry->soft_warned      = 0;
        strncpy(entry->container_id, req.container_id,
                MONITOR_NAME_LEN - 1);
        entry->container_id[MONITOR_NAME_LEN - 1] = '\0';
        INIT_LIST_HEAD(&entry->list);

        /* Insert under lock */
        mutex_lock(&list_lock);
        list_add_tail(&entry->list, &monitored_list);
        mutex_unlock(&list_lock);

        return 0;
    }

    /* ---------------------------------------------------------------
     * TODO 5: UNREGISTER — find and remove the entry
     * --------------------------------------------------------------- */
    printk(KERN_INFO
           "[container_monitor] Unregister request container=%s pid=%d\n",
           req.container_id, req.pid);

    {
        struct monitored_entry *entry, *tmp;
        int found = 0;

        mutex_lock(&list_lock);
        list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
            if (entry->pid == req.pid &&
                strncmp(entry->container_id, req.container_id,
                        MONITOR_NAME_LEN) == 0) {
                list_del(&entry->list);
                kfree(entry);
                found = 1;
                break;
            }
        }
        mutex_unlock(&list_lock);

        if (!found) {
            printk(KERN_WARNING
                   "[container_monitor] Unregister: not found"
                   " container=%s pid=%d\n",
                   req.container_id, req.pid);
            return -ENOENT;
        }
    }

    return 0;
}

/* --- Provided: file operations --- */
static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

/* --- Provided: Module Init --- */
static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    cl = class_create(DEVICE_NAME);
#else
    cl = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO
           "[container_monitor] Module loaded. Device: /dev/%s\n",
           DEVICE_NAME);
    return 0;
}

/* --- Provided: Module Exit --- */
static void __exit monitor_exit(void)
{
    struct monitored_entry *entry, *tmp;

    /* Stop the timer first so no new callbacks fire */
    timer_delete_sync(&monitor_timer);

    /* ---------------------------------------------------------------
     * TODO 6: Free all remaining monitored entries
     *
     * The timer is stopped so no concurrent access is possible.
     * Walk the list and kfree every node.
     * --------------------------------------------------------------- */
    mutex_lock(&list_lock);
    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
        printk(KERN_INFO
               "[container_monitor] Freeing entry container=%s pid=%d\n",
               entry->container_id, entry->pid);
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&list_lock);

    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervised multi-container memory monitor");
