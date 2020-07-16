// SPDX-License-Identifier: GPL-2.0
/*
 * nvmem framework core.
 *
 * Copyright (C) 2015 Srinivas Kandagatla <srinivas.kandagatla@linaro.org>
 * Copyright (C) 2013 Maxime Ripard <maxime.ripard@free-electrons.com>
 */

#include <linux/device.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/init.h>
#include <linux/kref.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "nvmem.h"

struct nvmem_cell {
	const char		*name;
	int			offset;
	int			bytes;
	int			bit_offset;
	int			nbits;
	struct nvmem_device	*nvmem;
	struct list_head	node;
};

static DEFINE_MUTEX(nvmem_mutex);
static DEFINE_IDA(nvmem_ida);

static DEFINE_MUTEX(nvmem_cell_mutex);
static LIST_HEAD(nvmem_cell_tables);

static DEFINE_MUTEX(nvmem_lookup_mutex);
static LIST_HEAD(nvmem_lookup_list);

static BLOCKING_NOTIFIER_HEAD(nvmem_notifier);


static int nvmem_reg_read(struct nvmem_device *nvmem, unsigned int offset,
			  void *val, size_t bytes)
{
	if (nvmem->reg_read)
		return nvmem->reg_read(nvmem->priv, offset, val, bytes);

	return -EINVAL;
}

static int nvmem_reg_write(struct nvmem_device *nvmem, unsigned int offset,
			   void *val, size_t bytes)
{
	int ret;

	if (nvmem->reg_write) {
		ret = nvmem->reg_write(nvmem->priv, offset, val, bytes);
		return ret;
	}

	return -EINVAL;
}

static void nvmem_release(struct device *dev)
{
	struct nvmem_device *nvmem = to_nvmem_device(dev);

	ida_simple_remove(&nvmem_ida, nvmem->id);
	kfree(nvmem);
}

static struct device_type nvmem_provider_type = {
	.release	= nvmem_release,
};

static struct bus_type nvmem_bus_type = {
	.name		= "nvmem",
};

/**
 * nvmem_register_notifier() - Register a notifier block for nvmem events.
 *
 * @nb: notifier block to be called on nvmem events.
 *
 * Return: 0 on success, negative error number on failure.
 */
int nvmem_register_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&nvmem_notifier, nb);
}
EXPORT_SYMBOL_GPL(nvmem_register_notifier);

/**
 * nvmem_unregister_notifier() - Unregister a notifier block for nvmem events.
 *
 * @nb: notifier block to be unregistered.
 *
 * Return: 0 on success, negative error number on failure.
 */
int nvmem_unregister_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&nvmem_notifier, nb);
}
EXPORT_SYMBOL_GPL(nvmem_unregister_notifier);

/**
 * nvmem_register() - Register a nvmem device for given nvmem_config.
 * Also creates an binary entry in /sys/bus/nvmem/devices/dev-name/nvmem
 *
 * @config: nvmem device configuration with which nvmem device is created.
 *
 * Return: Will be an ERR_PTR() on error or a valid pointer to nvmem_device
 * on success.
 */

struct nvmem_device *nvmem_register(const struct nvmem_config *config)
{
	struct nvmem_device *nvmem;
	int rval;

	if (!config->dev)
		return ERR_PTR(-EINVAL);

	nvmem = kzalloc(sizeof(*nvmem), GFP_KERNEL);
	if (!nvmem)
		return ERR_PTR(-ENOMEM);

	rval  = ida_simple_get(&nvmem_ida, 0, 0, GFP_KERNEL);
	if (rval < 0) {
		kfree(nvmem);
		return ERR_PTR(rval);
	}

	kref_init(&nvmem->refcnt);
	INIT_LIST_HEAD(&nvmem->cells);

	nvmem->id = rval;
	nvmem->owner = config->owner;
	if (!nvmem->owner && config->dev->driver)
		nvmem->owner = config->dev->driver->owner;
	nvmem->stride = config->stride ?: 1;
	nvmem->word_size = config->word_size ?: 1;
	nvmem->size = config->size;
	nvmem->dev.type = &nvmem_provider_type;
	nvmem->dev.bus = &nvmem_bus_type;
	nvmem->dev.parent = config->dev;
	nvmem->priv = config->priv;
	nvmem->type = config->type;
	nvmem->reg_read = config->reg_read;
	nvmem->reg_write = config->reg_write;

	if (config->id == -1 && config->name) {
		dev_set_name(&nvmem->dev, "%s", config->name);
	} else {
		dev_set_name(&nvmem->dev, "%s%d",
			     config->name ? : "nvmem",
			     config->name ? config->id : nvmem->id);
	}

	nvmem->read_only = config->read_only || !nvmem->reg_write;

	nvmem->dev.groups = nvmem_sysfs_get_groups(nvmem, config);

	device_initialize(&nvmem->dev);

	dev_dbg(&nvmem->dev, "Registering nvmem device %s\n", config->name);

	rval = device_add(&nvmem->dev);
	if (rval)
		goto err_put_device;

	blocking_notifier_call_chain(&nvmem_notifier, NVMEM_ADD, nvmem);

	return nvmem;

err_put_device:
	put_device(&nvmem->dev);

	return ERR_PTR(rval);
}
EXPORT_SYMBOL_GPL(nvmem_register);

static void nvmem_device_release(struct kref *kref)
{
	struct nvmem_device *nvmem;

	nvmem = container_of(kref, struct nvmem_device, refcnt);

	blocking_notifier_call_chain(&nvmem_notifier, NVMEM_REMOVE, nvmem);

	if (nvmem->flags & FLAG_COMPAT)
		device_remove_bin_file(nvmem->base_dev, &nvmem->eeprom);

	put_device(&nvmem->dev);
}

/**
 * nvmem_unregister() - Unregister previously registered nvmem device
 *
 * @nvmem: Pointer to previously registered nvmem device.
 */
void nvmem_unregister(struct nvmem_device *nvmem)
{
	kref_put(&nvmem->refcnt, nvmem_device_release);
}
EXPORT_SYMBOL_GPL(nvmem_unregister);

static void devm_nvmem_release(struct device *dev, void *res)
{
	nvmem_unregister(*(struct nvmem_device **)res);
}

/**
 * devm_nvmem_register() - Register a managed nvmem device for given
 * nvmem_config.
 * Also creates an binary entry in /sys/bus/nvmem/devices/dev-name/nvmem
 *
 * @dev: Device that uses the nvmem device.
 * @config: nvmem device configuration with which nvmem device is created.
 *
 * Return: Will be an ERR_PTR() on error or a valid pointer to nvmem_device
 * on success.
 */
struct nvmem_device *devm_nvmem_register(struct device *dev,
					 const struct nvmem_config *config)
{
	struct nvmem_device **ptr, *nvmem;

	ptr = devres_alloc(devm_nvmem_release, sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	nvmem = nvmem_register(config);

	if (!IS_ERR(nvmem)) {
		*ptr = nvmem;
		devres_add(dev, ptr);
	} else {
		devres_free(ptr);
	}

	return nvmem;
}
EXPORT_SYMBOL_GPL(devm_nvmem_register);

static int devm_nvmem_match(struct device *dev, void *res, void *data)
{
	struct nvmem_device **r = res;

	return *r == data;
}

/**
 * devm_nvmem_unregister() - Unregister previously registered managed nvmem
 * device.
 *
 * @dev: Device that uses the nvmem device.
 * @nvmem: Pointer to previously registered nvmem device.
 *
 * Return: Will be an negative on error or a zero on success.
 */
int devm_nvmem_unregister(struct device *dev, struct nvmem_device *nvmem)
{
	return devres_destroy(dev, devm_nvmem_release, devm_nvmem_match, nvmem);
}
EXPORT_SYMBOL(devm_nvmem_unregister);

static struct nvmem_device *__nvmem_device_get(void *data,
			int (*match)(struct device *dev, void *data))
{
	struct nvmem_device *nvmem = NULL;
	struct device *dev;

	mutex_lock(&nvmem_mutex);
	dev = bus_find_device(&nvmem_bus_type, NULL, data, match);
	if (dev)
		nvmem = to_nvmem_device(dev);
	mutex_unlock(&nvmem_mutex);
	if (!nvmem)
		return ERR_PTR(-EPROBE_DEFER);

	if (!try_module_get(nvmem->owner)) {
		dev_err(&nvmem->dev,
			"could not increase module refcount for cell %s\n",
			nvmem_dev_name(nvmem));

		put_device(&nvmem->dev);
		return ERR_PTR(-EINVAL);
	}

	kref_get(&nvmem->refcnt);

	return nvmem;
}

static void __nvmem_device_put(struct nvmem_device *nvmem)
{
	put_device(&nvmem->dev);
	module_put(nvmem->owner);
	kref_put(&nvmem->refcnt, nvmem_device_release);
}


/**
 * nvmem_device_find() - Find nvmem device with matching function
 *
 * @data: Data to pass to match function
 * @match: Callback function to check device
 *
 * Return: ERR_PTR() on error or a valid pointer to a struct nvmem_device
 * on success.
 */
struct nvmem_device *nvmem_device_find(void *data,
			int (*match)(struct device *dev, void *data))
{
	return __nvmem_device_get(data, match);
}
EXPORT_SYMBOL_GPL(nvmem_device_find);

static int devm_nvmem_device_match(struct device *dev, void *res, void *data)
{
	struct nvmem_device **nvmem = res;

	if (WARN_ON(!nvmem || !*nvmem))
		return 0;

	return *nvmem == data;
}

static void devm_nvmem_device_release(struct device *dev, void *res)
{
	nvmem_device_put(*(struct nvmem_device **)res);
}

/**
 * devm_nvmem_device_put() - put alredy got nvmem device
 *
 * @dev: Device that uses the nvmem device.
 * @nvmem: pointer to nvmem device allocated by devm_nvmem_cell_get(),
 * that needs to be released.
 */
void devm_nvmem_device_put(struct device *dev, struct nvmem_device *nvmem)
{
	int ret;

	ret = devres_destroy(dev, devm_nvmem_device_release,
			     devm_nvmem_device_match, nvmem);

	WARN_ON(ret);
}
EXPORT_SYMBOL_GPL(devm_nvmem_device_put);

/**
 * nvmem_device_put() - put alredy got nvmem device
 *
 * @nvmem: pointer to nvmem device that needs to be released.
 */
void nvmem_device_put(struct nvmem_device *nvmem)
{
	__nvmem_device_put(nvmem);
}
EXPORT_SYMBOL_GPL(nvmem_device_put);

/**
 * nvmem_device_read() - Read from a given nvmem device
 *
 * @nvmem: nvmem device to read from.
 * @offset: offset in nvmem device.
 * @bytes: number of bytes to read.
 * @buf: buffer pointer which will be populated on successful read.
 *
 * Return: length of successful bytes read on success and negative
 * error code on error.
 */
int nvmem_device_read(struct nvmem_device *nvmem,
		      unsigned int offset,
		      size_t bytes, void *buf)
{
	int rc;

	if (!nvmem)
		return -EINVAL;

	rc = nvmem_reg_read(nvmem, offset, buf, bytes);

	if (rc)
		return rc;

	return bytes;
}
EXPORT_SYMBOL_GPL(nvmem_device_read);

/**
 * nvmem_device_write() - Write cell to a given nvmem device
 *
 * @nvmem: nvmem device to be written to.
 * @offset: offset in nvmem device.
 * @bytes: number of bytes to write.
 * @buf: buffer to be written.
 *
 * Return: length of bytes written or negative error code on failure.
 */
int nvmem_device_write(struct nvmem_device *nvmem,
		       unsigned int offset,
		       size_t bytes, void *buf)
{
	int rc;

	if (!nvmem)
		return -EINVAL;

	rc = nvmem_reg_write(nvmem, offset, buf, bytes);

	if (rc)
		return rc;


	return bytes;
}
EXPORT_SYMBOL_GPL(nvmem_device_write);


/**
 * nvmem_dev_name() - Get the name of a given nvmem device.
 *
 * @nvmem: nvmem device.
 *
 * Return: name of the nvmem device.
 */
const char *nvmem_dev_name(struct nvmem_device *nvmem)
{
	return dev_name(&nvmem->dev);
}
EXPORT_SYMBOL_GPL(nvmem_dev_name);

static int __init nvmem_init(void)
{
	return bus_register(&nvmem_bus_type);
}

static void __exit nvmem_exit(void)
{
	bus_unregister(&nvmem_bus_type);
}

subsys_initcall(nvmem_init);
module_exit(nvmem_exit);

MODULE_AUTHOR("Srinivas Kandagatla <srinivas.kandagatla@linaro.org");
MODULE_AUTHOR("Maxime Ripard <maxime.ripard@free-electrons.com");
MODULE_DESCRIPTION("nvmem Driver Core");
MODULE_LICENSE("GPL v2");
