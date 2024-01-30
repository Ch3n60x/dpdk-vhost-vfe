/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024, NVIDIA CORPORATION & AFFILIATES.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/vfio.h>
#include <unistd.h>
#include <syslog.h>

#include <virtio_ha.h>

#define log_error(M, ...) \
	syslog(LOG_ERR, "[VIRTIO HA ERR] %s:%d:%s: " M "\n", \
	       __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define log_info(M, ...) \
	syslog(LOG_INFO,  "[VIRTIO HA INFO]  %s:%d:%s: " M "\n", \
	       __FILE__, __LINE__, __func__, ##__VA_ARGS__)

enum ha_msg_hdlr_res {
	HA_MSG_HDLR_ERR = 0, /* Message handling error */
	HA_MSG_HDLR_SUCCESS = 1, /* Message handling success */
	HA_MSG_HDLR_REPLY = 2, /* Message handling success and need reply */
};

typedef void (*fd_cb)(int fd, void *data);
typedef int (*ha_message_handler_t)(struct virtio_ha_msg *msg);

struct ha_event_handler {
	void *data;
	int sock;
	fd_cb cb;
};

static struct virtio_ha_device_list hs;
static struct ha_event_handler msg_hdlr;
static struct virtio_ha_msg *msg;

static int
ha_server_app_query_pf_list(struct virtio_ha_msg *msg)
{
	struct virtio_ha_pf_dev *dev;
	struct virtio_dev_name *pf_name;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	uint32_t i = 0;

	if (hs.nr_pf == 0)
		return HA_MSG_HDLR_REPLY;

	msg->iov.iov_len = hs.nr_pf * sizeof(struct virtio_dev_name);
	msg->iov.iov_base = malloc(msg->iov.iov_len);
	if (msg->iov.iov_base == NULL) {
		log_error("Failed to alloc pf list");
		return HA_MSG_HDLR_ERR;
	}

	pf_name = (struct virtio_dev_name *)msg->iov.iov_base;
	TAILQ_FOREACH(dev, list, next) {
		memcpy(pf_name + i, &dev->pf_name, sizeof(struct virtio_dev_name));
		i++;
	}

	msg->hdr.size = msg->iov.iov_len;

	return HA_MSG_HDLR_REPLY;
}

static int
ha_server_app_query_vf_list(struct virtio_ha_msg *msg)
{
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct vdpa_vf_with_devargs *vf;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	uint32_t nr_vf, i = 0;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			nr_vf = dev->nr_vf;
			break;
		}
	}

	if (vf_list == NULL || nr_vf == 0)
		return HA_MSG_HDLR_REPLY;

	msg->iov.iov_len = nr_vf * sizeof(struct vdpa_vf_with_devargs);
	msg->iov.iov_base = malloc(msg->iov.iov_len);
	if (msg->iov.iov_base == NULL) {
		log_error("Failed to alloc vf list");
		return HA_MSG_HDLR_ERR;
	}

	vf = (struct vdpa_vf_with_devargs *)msg->iov.iov_base;
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		memcpy(vf + i, &vf_dev->vf_devargs, sizeof(struct vdpa_vf_with_devargs));
		i++;		
	}

	msg->hdr.size = msg->iov.iov_len;

	return HA_MSG_HDLR_REPLY;
}

static int
ha_server_app_query_pf_ctx(struct virtio_ha_msg *msg)
{
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;

	if (hs.nr_pf == 0)
		return HA_MSG_HDLR_REPLY;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			msg->nr_fds = 2;
			msg->fds[0] = dev->pf_ctx.vfio_group_fd;
			msg->fds[1] = dev->pf_ctx.vfio_device_fd;
			break;
		}
	}

	return HA_MSG_HDLR_REPLY;
}

static int
ha_server_app_query_vf_ctx(struct virtio_ha_msg *msg)
{
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct vdpa_vf_with_devargs *vf;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	uint32_t nr_vf;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			nr_vf = dev->nr_vf;
			break;
		}
	}

	if (vf_list == NULL || nr_vf == 0)
		return HA_MSG_HDLR_REPLY;

	vf = (struct vdpa_vf_with_devargs *)msg->iov.iov_base;
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		if (!strcmp(vf_dev->vf_devargs.vf_name.dev_bdf, vf->vf_name.dev_bdf)) {
			msg->iov.iov_len = sizeof(struct virtio_vdpa_dma_mem) +
				vf_dev->vf_ctx.mem.nregions * sizeof(struct virtio_vdpa_mem_region);
			msg->iov.iov_base = malloc(msg->iov.iov_len);
			if (msg->iov.iov_base == NULL) {
				log_error("Failed to alloc vf mem table");
				return HA_MSG_HDLR_ERR;
			}
			memcpy(msg->iov.iov_base, &vf_dev->vf_ctx.mem, msg->iov.iov_len);
			msg->nr_fds = 3;
			msg->fds[0] = vf_dev->vf_ctx.vfio_container_fd;
			msg->fds[1] = vf_dev->vf_ctx.vfio_group_fd;
			msg->fds[2] = vf_dev->vf_ctx.vfio_device_fd;
			break;
		}
	}

	msg->hdr.size = msg->iov.iov_len;

	return HA_MSG_HDLR_REPLY;
}

static int
ha_server_pf_store_ctx(struct virtio_ha_msg *msg)
{
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;

	if (msg->nr_fds != 2)
		return HA_MSG_HDLR_SUCCESS;

	/* Assume HA client will not re-set ctx */
	dev = malloc(sizeof(struct virtio_ha_pf_dev));
	if (dev == NULL) {
		log_error("Failed to alloc pf device");
		return HA_MSG_HDLR_ERR;
	}

	memset(dev, 0, sizeof(struct virtio_ha_pf_dev));
	TAILQ_INIT(&dev->vf_list);
	dev->nr_vf = 0;
	strncpy(dev->pf_name.dev_bdf, msg->hdr.bdf, PCI_PRI_STR_SIZE);
	dev->pf_ctx.vfio_group_fd = msg->fds[0];
	dev->pf_ctx.vfio_device_fd = msg->fds[1];

	TAILQ_INSERT_TAIL(list, dev, next);
	hs.nr_pf++;

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_pf_remove_ctx(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	bool found = false;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	if (vf_list) {
		TAILQ_FOREACH(vf_dev, vf_list, next) {
			close(vf_dev->vf_ctx.vfio_device_fd);
			close(vf_dev->vf_ctx.vfio_group_fd);
			close(vf_dev->vf_ctx.vfio_container_fd);
			free(vf_dev);
		}
	}

	hs.nr_pf--;
	TAILQ_REMOVE(list, dev, next);
	close(dev->pf_ctx.vfio_device_fd);
	close(dev->pf_ctx.vfio_group_fd);
	free(dev);

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_vf_store_devarg_vfio_fds(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	size_t len;
	bool found = false;

	if (msg->nr_fds != 3)
		return HA_MSG_HDLR_SUCCESS;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	/* To avoid memory realloc when mem table entry number changes, alloc for max entry num */
	len = sizeof(struct virtio_ha_vf_dev) +
		sizeof(struct virtio_vdpa_mem_region) * VIRTIO_HA_MAX_MEM_REGIONS;
	vf_dev = malloc(len);
	if (vf_dev == NULL) {
		log_error("Failed to alloc vf device");
		return HA_MSG_HDLR_ERR;
	}

	memset(vf_dev, 0, len);
	memcpy(&vf_dev->vf_devargs, msg->iov.iov_base, msg->iov.iov_len);
	vf_dev->vf_ctx.vfio_container_fd = msg->fds[0];
	vf_dev->vf_ctx.vfio_group_fd = msg->fds[1];
	vf_dev->vf_ctx.vfio_device_fd = msg->fds[2];
	vf_dev->vhost_fd = -1;

	TAILQ_INSERT_TAIL(vf_list, vf_dev, next);
	dev->nr_vf++;

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_store_vhost_fd(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct virtio_dev_name *vf_name;
	bool found = false;

	if (msg->nr_fds != 1)
		return HA_MSG_HDLR_SUCCESS;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	vf_name = (struct virtio_dev_name *)msg->iov.iov_base;
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		if (!strcmp(vf_dev->vf_devargs.vf_name.dev_bdf, vf_name->dev_bdf)) {
			vf_dev->vhost_fd = msg->fds[0];
			break;
		}
	}

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_store_dma_tbl(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct virtio_dev_name *vf_name;
	struct virtio_vdpa_dma_mem *mem;
	size_t len;
	bool found = false;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	vf_name = (struct virtio_dev_name *)msg->iov.iov_base;
	len = msg->iov.iov_len - sizeof(struct virtio_dev_name);
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		if (!strcmp(vf_dev->vf_devargs.vf_name.dev_bdf, vf_name->dev_bdf)) {
			mem = (struct virtio_vdpa_dma_mem *)(vf_name + 1);
			memcpy(&vf_dev->vf_ctx.mem, mem, len);
			break;
		}
	}

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_remove_devarg_vfio_fds(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct virtio_dev_name *vf_name;
	bool found = false;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	found = false;
	vf_name = (struct virtio_dev_name *)msg->iov.iov_base;
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		if (!strcmp(vf_dev->vf_devargs.vf_name.dev_bdf, vf_name->dev_bdf)) {
			found = true;
			break;
		}
	}

	if (found) {
		dev->nr_vf--;
		TAILQ_REMOVE(vf_list, vf_dev, next);
		close(vf_dev->vf_ctx.vfio_device_fd);
		close(vf_dev->vf_ctx.vfio_group_fd);
		close(vf_dev->vf_ctx.vfio_container_fd);
		free(vf_dev);
	}

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_remove_vhost_fd(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct virtio_dev_name *vf_name;
	bool found = false;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	vf_name = (struct virtio_dev_name *)msg->iov.iov_base;
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		if (!strcmp(vf_dev->vf_devargs.vf_name.dev_bdf, vf_name->dev_bdf)) {
			close(vf_dev->vhost_fd);
			vf_dev->vhost_fd = -1;
			break;
		}
	}

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_remove_dma_tbl(struct virtio_ha_msg *msg)
{
	struct virtio_ha_vf_dev_list *vf_list = NULL;
	struct virtio_ha_pf_dev_list *list = &hs.pf_list;
	struct virtio_ha_pf_dev *dev;
	struct virtio_ha_vf_dev *vf_dev;
	struct virtio_dev_name *vf_name;
	struct virtio_vdpa_dma_mem *mem;
	struct vfio_iommu_type1_dma_unmap dma_unmap = {};
	int ret;
	uint32_t i;
	bool found = false;

	TAILQ_FOREACH(dev, list, next) {
		if (!strcmp(dev->pf_name.dev_bdf, msg->hdr.bdf)) {
			vf_list = &dev->vf_list;
			found = true;
			break;
		}
	}

	if (!found)
		return HA_MSG_HDLR_SUCCESS;

	vf_name = (struct virtio_dev_name *)msg->iov.iov_base;
	TAILQ_FOREACH(vf_dev, vf_list, next) {
		if (!strcmp(vf_dev->vf_devargs.vf_name.dev_bdf, vf_name->dev_bdf)) {
			mem = &vf_dev->vf_ctx.mem;
			dma_unmap.argsz = sizeof(struct vfio_iommu_type1_dma_unmap);
			for (i = 0; i < mem->nregions; i++) {
				dma_unmap.size = mem->regions[i].size;
				dma_unmap.iova = mem->regions[i].guest_phys_addr;
				ret = ioctl(vf_dev->vf_ctx.vfio_container_fd, VFIO_IOMMU_UNMAP_DMA,
						&dma_unmap);
				if (ret) {
					log_error("Cannot clear DMA remapping");
				} else if (dma_unmap.size != mem->regions[i].size) {
					log_error("Unexpected size %"PRIu64
						" of DMA remapping cleared instead of %"PRIu64,
						(uint64_t)dma_unmap.size, mem->regions[i].size);
				}
			}
			break;
		}
	}

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_store_global_cfd(struct virtio_ha_msg *msg)
{
	if (msg->nr_fds != 1)
		return HA_MSG_HDLR_SUCCESS;

	hs.global_cfd = msg->fds[0];
	printf("Save global cfd: %d\n", hs.global_cfd);

	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_query_global_cfd(struct virtio_ha_msg *msg)
{
	if (hs.global_cfd == -1)
		return HA_MSG_HDLR_REPLY;

	msg->nr_fds = 1;
	msg->fds[0] = hs.global_cfd;
	printf("Query global cfd: %d\n", hs.global_cfd);

	return HA_MSG_HDLR_REPLY;
}

static int
ha_server_global_store_dma_map(struct virtio_ha_msg *msg)
{
	struct virtio_ha_global_dma_entry *entry;
	struct virtio_ha_global_dma_map *map;
	bool found = false;

	map = (struct virtio_ha_global_dma_map *)msg->iov.iov_base;
	TAILQ_FOREACH(entry, &hs.dma_tbl, next) {
		/* vDPA application should not send entries that have the same iova but different size */
		if (map->iova == entry->map.iova) {
			found = true;
			break;
		}
	}

	if (!found) {
		entry = malloc(sizeof(struct virtio_ha_global_dma_entry));
		if (!entry) {
			log_error("Failed to alloc dma entry");
			return HA_MSG_HDLR_SUCCESS;
		}
		memcpy(&entry->map, map, sizeof(struct virtio_ha_global_dma_map));
		TAILQ_INSERT_TAIL(&hs.dma_tbl, entry, next);
	}

	printf("DMA MAP STORE: iova(0x%lx), len(0x%lx)\n", map->iova, map->size);
	return HA_MSG_HDLR_SUCCESS;
}

static int
ha_server_global_remove_dma_map(struct virtio_ha_msg *msg)
{
	struct virtio_ha_global_dma_entry *entry;
	struct virtio_ha_global_dma_map *map;
	bool found = false;

	map = (struct virtio_ha_global_dma_map *)msg->iov.iov_base;
	TAILQ_FOREACH(entry, &hs.dma_tbl, next) {
		/* vDPA application should not send entries that have the same iova but different size */
		if (map->iova == entry->map.iova) {
			found = true;
			break;
		}
	}

	if (found) {
		TAILQ_REMOVE(&hs.dma_tbl, entry, next);
		free(entry);
	}
	printf("DMA MAP REMOVE: iova(0x%lx), len(0x%lx)\n", map->iova, map->size);
	return HA_MSG_HDLR_SUCCESS;
}

static void
ha_server_cleanup_global_dma(void)
{
	struct virtio_ha_global_dma_entry *entry, *next;
	struct vfio_iommu_type1_dma_unmap dma_unmap = {};
	int ret;

	dma_unmap.argsz = sizeof(struct vfio_iommu_type1_dma_unmap);
	dma_unmap.flags = VFIO_DMA_UNMAP_FLAG_ALL;
	dma_unmap.size = 0;
	dma_unmap.iova = 0;
	ret = ioctl(hs.global_cfd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	if (ret) {
		printf("Cannot clear DMA remapping");
	}
#if 0
	for (entry = TAILQ_FIRST(&hs.dma_tbl);
		 entry != NULL; entry = next) {
		next = TAILQ_NEXT(entry, next);
		dma_unmap.argsz = sizeof(struct vfio_iommu_type1_dma_unmap);
		dma_unmap.size = entry->map.size;
		dma_unmap.iova = entry->map.iova;
		ret = ioctl(hs.global_cfd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
		if (ret) {
			printf("Cannot clear DMA remapping");
		} else if (dma_unmap.size != entry->map.size) {
			printf("Unexpected size %"PRIu64
				" of DMA remapping cleared instead of %"PRIu64,
				(uint64_t)dma_unmap.size, entry->map.size);
		}
		printf("DMA MAP CLEANUP: iova(0x%lx), len(0x%lx)\n", entry->map.iova, entry->map.size);
		TAILQ_REMOVE(&hs.dma_tbl, entry, next);
		free(entry);
	}
#endif
}

static int
ha_server_global_store_mem_fd(struct virtio_ha_msg *msg)
{
	struct virtio_ha_global_mem_info *info;
	void *addr = (void *)(uintptr_t)0x140000000;

	if (msg->nr_fds != 1)
		return HA_MSG_HDLR_SUCCESS;

	hs.mem_fd = msg->fds[0];
	printf("Save global mem fd: %d\n", hs.mem_fd);
	info = (struct virtio_ha_global_mem_info *)msg->iov.iov_base;
	memcpy(&hs.mem_info, info, sizeof(struct virtio_ha_global_mem_info));

	hs.mem_va = mmap(addr, info->sz, PROT_READ | PROT_WRITE, info->flags, hs.mem_fd,
			info->off);

	if (hs.mem_va == MAP_FAILED) {
		printf("mmap failed\n");
	}
	printf("try to map 0x140000000, finally at %p\n", hs.mem_va);
	return HA_MSG_HDLR_SUCCESS;
}

static ha_message_handler_t ha_message_handlers[VIRTIO_HA_MESSAGE_MAX] = {//TO-DO: add payload sz check and more log in handler
	[VIRTIO_HA_APP_QUERY_PF_LIST] = ha_server_app_query_pf_list,
	[VIRTIO_HA_APP_QUERY_VF_LIST] = ha_server_app_query_vf_list,
	[VIRTIO_HA_APP_QUERY_PF_CTX] = ha_server_app_query_pf_ctx,
	[VIRTIO_HA_APP_QUERY_VF_CTX] = ha_server_app_query_vf_ctx,
	[VIRTIO_HA_PF_STORE_CTX] = ha_server_pf_store_ctx,
	[VIRTIO_HA_PF_REMOVE_CTX] = ha_server_pf_remove_ctx,
	[VIRTIO_HA_VF_STORE_DEVARG_VFIO_FDS] = ha_server_vf_store_devarg_vfio_fds,
	[VIRTIO_HA_VF_STORE_VHOST_FD] = ha_server_store_vhost_fd,
	[VIRTIO_HA_VF_STORE_DMA_TBL] = ha_server_store_dma_tbl,
	[VIRTIO_HA_VF_REMOVE_DEVARG_VFIO_FDS] = ha_server_remove_devarg_vfio_fds,
	[VIRTIO_HA_VF_REMOVE_VHOST_FD] = ha_server_remove_vhost_fd,
	[VIRTIO_HA_VF_REMOVE_DMA_TBL] = ha_server_remove_dma_tbl,
	[VIRTIO_HA_GLOBAL_STORE_CONTAINER] = ha_server_store_global_cfd,
	[VIRTIO_HA_GLOBAL_QUERY_CONTAINER] = ha_server_query_global_cfd,
	[VIRTIO_HA_GLOBAL_STORE_DMA_MAP] = ha_server_global_store_dma_map,
	[VIRTIO_HA_GLOBAL_REMOVE_DMA_MAP] = ha_server_global_remove_dma_map,
	[VIRTIO_HA_GLOBAL_STORE_MEM_FD] = ha_server_global_store_mem_fd,
};

static void
ha_message_handler(int fd, __attribute__((__unused__)) void *data)
{
	int ret;

	virtio_ha_reset_msg(msg);

	ret = virtio_ha_recv_msg(fd, msg);
	if (ret <= 0) {
		if (ret < 0)
			log_error("Failed to recv ha msg");
		else
			log_error("Client closed");
		return;
	}

	//TO-DO: add check of recv count?

	ret = ha_message_handlers[msg->hdr.type](msg);
	switch (ret) {
	case HA_MSG_HDLR_ERR:
	case HA_MSG_HDLR_SUCCESS:
		return;
	case HA_MSG_HDLR_REPLY:
		ret = virtio_ha_send_msg(fd, msg);
		if (ret != (int)(msg->hdr.size + sizeof(msg->hdr))) {//TO-DO: change check, also clean-up ret value of send/recv
			if (ret < 0)
				log_error("Failed to send ha msg");
			else
				log_error("Failed to send complete ha msg");
		}
	default:
		break;
	}

	return;
}

static void
add_connection(int fd, void *data)
{
	struct epoll_event event;
	int sock, epfd;

	sock = accept(fd, NULL, NULL);
	if (sock < 0) {
		log_error("Failed to accept connection");
		return;
	}

	msg_hdlr.sock = sock;
	printf("msg hdlr sock %d\n", sock);
	msg_hdlr.cb = ha_message_handler;
	msg_hdlr.data = NULL;

	epfd = *(int *)data;
	event.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	event.data.ptr = &msg_hdlr;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &event) < 0)
		log_error("Failed to epoll ctl add for message");

	return;
}

int
main(__attribute__((__unused__)) int argc, __attribute__((__unused__)) char *argv[])
{
	struct sockaddr_un addr;
	struct epoll_event event, ev[2];
	struct ha_event_handler hdl, *handler;
	int sock, epfd, nev, i;

	msg = virtio_ha_alloc_msg();
	if (!msg) {
		log_error("Failed to alloc ha msg");
		return -1;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		log_error("Failed to create socket");
		goto err;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, VIRTIO_HA_UDS_PATH);
	unlink(VIRTIO_HA_UDS_PATH);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_error("Failed to bind socket");
		goto err;
	}

	if (listen(sock, 5) < 0) {
		log_error("Failed on socket listen");
		goto err;
	}

	epfd = epoll_create(1);
	if (epfd < 0) {
		log_error("Failed to create epoll fd");
		goto err;
	}

	TAILQ_INIT(&hs.pf_list);
	TAILQ_INIT(&hs.dma_tbl);
	hs.nr_pf = 0;
	hs.global_cfd = -1;

	hdl.sock = sock;
	printf("conn hdlr sock %d\n", sock);
	hdl.cb = add_connection;
	hdl.data = &epfd;
	event.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	event.data.ptr = &hdl;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &event) < 0) {
		log_error("Failed to epoll ctl add for connection");
		goto err;
	}

	while (1) {
		nev = epoll_wait(epfd, ev, 2, -1);
		for (i = 0; i < nev; i++) {
			handler = (struct ha_event_handler *)ev[i].data.ptr;
			if ((ev[i].events & EPOLLERR) || (ev[i].events & EPOLLHUP)) {
				if (epoll_ctl(epfd, EPOLL_CTL_DEL, handler->sock, &ev[i]) < 0)
					log_error("Failed to epoll ctl del for fd %d", handler->sock);
				close(handler->sock);
				ha_server_cleanup_global_dma();
				munmap(hs.mem_va, hs.mem_info.sz);
			} else { /* EPOLLIN */
				handler->cb(handler->sock, handler->data);
			}
		}
	}

	return 0;

err:
	virtio_ha_free_msg(msg);
	return -1;
}
