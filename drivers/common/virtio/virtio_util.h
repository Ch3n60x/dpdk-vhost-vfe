/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 NVIDIA Corporation & Affiliates
 */

#ifndef _VIRTIO_UTIL_H_
#define _VIRTIO_UTIL_H_

enum virtio_errno
{
#define VFE_VDPA_SUCCESS	(0)	/* Successful command */
#define VFE_VDPA_ERR_BASE	(1000)	/* Global error base */
	VFE_VDPA_ERR_NO_PF_NAME = VFE_VDPA_ERR_BASE, /*0*/
	VFE_VDPA_ERR_NO_PF_DEVICE,
	VFE_VDPA_ERR_NO_VF_NAME,
	VFE_VDPA_ERR_NO_VF_DEVICE,
	VFE_VDPA_ERR_VFIO_DEV_FD,
	VFE_VDPA_ERR_EXCEED_LIMIT, /*5*/
	VFE_VDPA_ERR_RESET_DEVICE_TIMEOUT,
	VFE_VDPA_ERR_DEVARGS_PARSE,
	VFE_VDPA_ERR_ADD_PF_ALREADY_ADD,
	VFE_VDPA_ERR_DEVICE_PROBE_FAIL,
	VFE_VDPA_ERR_ADD_PF_DEVICEID_NOT_SUPPORT, /*10*/
	VFE_VDPA_ERR_ADD_PF_FEATURE_NOT_MEET,
	VFE_VDPA_ERR_ADD_PF_ALLOC_ADMIN_QUEUE,
	VFE_VDPA_ERR_REMOVE_PF_WITH_VF,
	VFE_VDPA_ERR_ADD_VF_ALREADY_ADD,
	VFE_VDPA_ERR_ADD_VF_NO_VFID, /*15*/
	VFE_VDPA_ERR_ADD_VF_CREATE_VFIO_CONTAINER,
	VFE_VDPA_ERR_ADD_VF_VFIO_CONTAINER_GROUP_BIND,
	VFE_VDPA_ERR_ADD_VF_GET_IOMMU_GROUP,
	VFE_VDPA_ERR_ADD_VF_ALLOC,
	VFE_VDPA_ERR_ADD_VF_REGISTER_DEVICE, /*20*/
	VFE_VDPA_ERR_ADD_VF_QUEUES_ALLOC,
	VFE_VDPA_ERR_ADD_VF_NO_VECTOR, 
	VFE_VDPA_ERR_ADD_VF_INTERRUPT_ALLOC,
	VFE_VDPA_ERR_ADD_VF_REGISTER_INTERRUPT,
	VFE_VDPA_ERR_ADD_VF_ENABLE_INTERRUPT, /*25*/
	VFE_VDPA_ERR_ADD_VF_BAR_COPY,
	VFE_VDPA_ERR_ADD_VF_SET_STATUS_QUIESCED,
	VFE_VDPA_ERR_ADD_VF_SET_STATUS_FREEZED,
	VFE_VDPA_ERR_ADD_VF_EXCEED_VPORT_LIMIT,
	VFE_VDPA_ERR_ADD_VF_NO_ACCESS_SOCKET_PATH, /*30*/
	VFE_VDPA_ERR_ADD_VF_VHOST_DRIVER_REGISTER,
	VFE_VDPA_ERR_ADD_VF_VDPA_GET_FEATURES,
	VFE_VDPA_ERR_ADD_VF_VHOST_DRIVER_SET_FEATURES,
	VFE_VDPA_ERR_ADD_VF_VHOST_DRIVER_CALLBACK_REGISTER,
	VFE_VDPA_ERR_ADD_VF_VHOST_DRIVER_ATTACH_VDPA_DEVICE, /*35*/
	VFE_VDPA_ERR_ADD_VF_VHOST_DRIVER_START,
	VFE_VDPA_ERR_ADD_VF_IOMMU_DOMAIN_ALLOC,
	VFE_VDPA_ERR_ADD_VF_VHOST_SOCK_EXIST,
	VFE_VDPA_ERR_ADD_VF_EXCEED_MAX_GROUP_NUM,
	VFE_VDPA_ERR_REMOVE_VF_RESTORE_IN_PROGRESS, /*40*/
	VFE_VDPA_ERR_MAX_NUM,
};

#endif
