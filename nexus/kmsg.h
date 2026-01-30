// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Dario Casalinuovo
 */

#ifndef __VOS_NEXUS_KMSG
#define __VOS_NEXUS_KMSG

#define KMSG_HEADER_SIZE   28
#define KMSG_BUFFER_SIZE   512

#ifdef __KERNEL__

#define B_INT32_TYPE   0x4C4F4E47
#define B_INT64_TYPE   0x4C4C4E47
#define B_STRING_TYPE  0x43535452
#define B_UINT64_TYPE  0x554C4C47

#endif

typedef int32_t port_id;
typedef int32_t team_id;

struct kmsg_builder {
    char	*buffer;
    size_t	capacity;
    size_t	size;

    size_t	last_field_offset;
};

static inline size_t kmsgalign4(size_t n)
{
	return (n + 3) & ~3;
}

static inline void kmsg_init(struct kmsg_builder *msg, char *buffer,
	size_t size, uint32_t what)
{
    msg->buffer = buffer;
    msg->capacity = size;
    msg->size = KMSG_HEADER_SIZE;
    msg->last_field_offset = 0;

    memset(buffer, 0, KMSG_HEADER_SIZE);

    *(uint32_t *)(buffer + 0)  = 0x6b4d7347; // 'kMsg'
    *(int32_t *)(buffer + 4)   = KMSG_HEADER_SIZE;
    *(uint32_t *)(buffer + 8)  = what;
    *(int32_t *)(buffer + 12)  = -1;
    *(int32_t *)(buffer + 16)  = -1;
    *(int32_t *)(buffer + 20)  = -1;
    *(int32_t *)(buffer + 24)  = -1;
}

static inline int kmsg_add_field(struct kmsg_builder *msg, const char *name,
	uint32_t type, const void *data, int32_t size, int32_t count)
{
    size_t name_len = strlen(name) + 1;
    size_t header_size = kmsgalign4(18 + name_len);
    size_t data_size = size * count;
    size_t field_size = header_size + kmsgalign4(data_size);
    char *p;

    msg->size = kmsgalign4(msg->size);

    if (msg->size + field_size > msg->capacity)
        return -1;

    p = msg->buffer + msg->size;
    msg->last_field_offset = msg->size;

    *(uint32_t *)(p + 0)  = type;
    *(int32_t *)(p + 4)   = size;
    *(int32_t *)(p + 8)   = count;
    *(int32_t *)(p + 12)  = (int32_t)field_size;
    *(int16_t *)(p + 16)  = (int16_t)header_size;
    memcpy(p + 18, name, name_len);

    if (header_size > 18 + name_len)
        memset(p + 18 + name_len, 0, header_size - 18 - name_len);

    memcpy(p + header_size, data, data_size);

    if (kmsgalign4(data_size) > data_size)
        memset(p + header_size + data_size, 0, kmsgalign4(data_size) - data_size);

    msg->size += field_size;
    return 0;
}

static inline int kmsg_add_data(struct kmsg_builder *msg, const char *name,
    uint32_t type, const void *data, size_t len)
{
    size_t name_len = strlen(name) + 1;
    size_t header_size = kmsgalign4(18 + name_len);
    size_t value_header_size = 4;
    size_t aligned_data_offset = kmsgalign4(value_header_size);
    size_t value_total = aligned_data_offset + len;
    size_t field_size = header_size + kmsgalign4(value_total);
    char *p;

    msg->size = kmsgalign4(msg->size);

    if (msg->size + field_size > msg->capacity)
        return -1;

    p = msg->buffer + msg->size;
    msg->last_field_offset = msg->size;

    *(uint32_t *)(p + 0)  = type;
    *(int32_t *)(p + 4)   = -1;
    *(int32_t *)(p + 8)   = 1;
    *(int32_t *)(p + 12)  = (int32_t)field_size;
    *(int16_t *)(p + 16)  = (int16_t)header_size;
    memcpy(p + 18, name, name_len);

    if (header_size > 18 + name_len)
        memset(p + 18 + name_len, 0, header_size - 18 - name_len);

    p += header_size;
    *(int32_t *)p = (int32_t)len;

    if (aligned_data_offset > 4)
        memset(p + 4, 0, aligned_data_offset - 4);

    memcpy(p + aligned_data_offset, data, len);

    if (kmsgalign4(value_total) > value_total)
        memset(p + value_total, 0, kmsgalign4(value_total) - value_total);

    msg->size += field_size;
    return 0;
}

static inline void kmsg_add_uint64(struct kmsg_builder *msg, const char *name,
	uint64_t val)
{
    kmsg_add_field(msg, name, B_UINT64_TYPE, &val, sizeof(uint64_t), 1);
}

static inline void kmsg_add_int32(struct kmsg_builder *msg, const char *name, int32_t val)
{
    kmsg_add_field(msg, name, B_INT32_TYPE, &val, sizeof(int32_t), 1);
}

static inline void kmsg_add_int64(struct kmsg_builder *msg, const char *name, int64_t val)
{
    kmsg_add_field(msg, name, B_INT64_TYPE, &val, sizeof(int64_t), 1);
}

static inline void kmsg_add_string(struct kmsg_builder *msg, const char *name,
	const char *val)
{
    size_t len = strlen(val) + 1;
    kmsg_add_data(msg, name, B_STRING_TYPE, val, len);
}

static inline void kmsg_finalize(struct kmsg_builder *msg, port_id port, uint32_t token)
{
	// Header size
    *(int32_t *)(msg->buffer + 4) = (int32_t)msg->size;
    // Delivery info
    *(int32_t *)(msg->buffer + 16) = (int32_t)token;
    *(int32_t *)(msg->buffer + 20) = port;
}

#endif /* __VOS_NEXUS_KMSG */
