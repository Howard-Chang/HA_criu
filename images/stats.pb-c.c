/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: stats.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "stats.pb-c.h"
void   dump_stats_entry__init
                     (DumpStatsEntry         *message)
{
  static DumpStatsEntry init_value = DUMP_STATS_ENTRY__INIT;
  *message = init_value;
}
size_t dump_stats_entry__get_packed_size
                     (const DumpStatsEntry *message)
{
  assert(message->base.descriptor == &dump_stats_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t dump_stats_entry__pack
                     (const DumpStatsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &dump_stats_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t dump_stats_entry__pack_to_buffer
                     (const DumpStatsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &dump_stats_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
DumpStatsEntry *
       dump_stats_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (DumpStatsEntry *)
     protobuf_c_message_unpack (&dump_stats_entry__descriptor,
                                allocator, len, data);
}
void   dump_stats_entry__free_unpacked
                     (DumpStatsEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &dump_stats_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   restore_stats_entry__init
                     (RestoreStatsEntry         *message)
{
  static RestoreStatsEntry init_value = RESTORE_STATS_ENTRY__INIT;
  *message = init_value;
}
size_t restore_stats_entry__get_packed_size
                     (const RestoreStatsEntry *message)
{
  assert(message->base.descriptor == &restore_stats_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t restore_stats_entry__pack
                     (const RestoreStatsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &restore_stats_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t restore_stats_entry__pack_to_buffer
                     (const RestoreStatsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &restore_stats_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
RestoreStatsEntry *
       restore_stats_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (RestoreStatsEntry *)
     protobuf_c_message_unpack (&restore_stats_entry__descriptor,
                                allocator, len, data);
}
void   restore_stats_entry__free_unpacked
                     (RestoreStatsEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &restore_stats_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   stats_entry__init
                     (StatsEntry         *message)
{
  static StatsEntry init_value = STATS_ENTRY__INIT;
  *message = init_value;
}
size_t stats_entry__get_packed_size
                     (const StatsEntry *message)
{
  assert(message->base.descriptor == &stats_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t stats_entry__pack
                     (const StatsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &stats_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t stats_entry__pack_to_buffer
                     (const StatsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &stats_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
StatsEntry *
       stats_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (StatsEntry *)
     protobuf_c_message_unpack (&stats_entry__descriptor,
                                allocator, len, data);
}
void   stats_entry__free_unpacked
                     (StatsEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &stats_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor dump_stats_entry__field_descriptors[14] =
{
  {
    "freezing_time",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, freezing_time),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "frozen_time",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, frozen_time),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "memdump_time",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, memdump_time),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "memwrite_time",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, memwrite_time),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pages_scanned",
    5,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, pages_scanned),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pages_skipped_parent",
    6,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, pages_skipped_parent),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pages_written",
    7,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, pages_written),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "irmap_resolve",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(DumpStatsEntry, has_irmap_resolve),
    offsetof(DumpStatsEntry, irmap_resolve),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pages_lazy",
    9,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(DumpStatsEntry, pages_lazy),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "page_pipes",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(DumpStatsEntry, has_page_pipes),
    offsetof(DumpStatsEntry, page_pipes),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "page_pipe_bufs",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(DumpStatsEntry, has_page_pipe_bufs),
    offsetof(DumpStatsEntry, page_pipe_bufs),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shpages_scanned",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(DumpStatsEntry, has_shpages_scanned),
    offsetof(DumpStatsEntry, shpages_scanned),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shpages_skipped_parent",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(DumpStatsEntry, has_shpages_skipped_parent),
    offsetof(DumpStatsEntry, shpages_skipped_parent),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shpages_written",
    14,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(DumpStatsEntry, has_shpages_written),
    offsetof(DumpStatsEntry, shpages_written),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned dump_stats_entry__field_indices_by_name[] = {
  0,   /* field[0] = freezing_time */
  1,   /* field[1] = frozen_time */
  7,   /* field[7] = irmap_resolve */
  2,   /* field[2] = memdump_time */
  3,   /* field[3] = memwrite_time */
  10,   /* field[10] = page_pipe_bufs */
  9,   /* field[9] = page_pipes */
  8,   /* field[8] = pages_lazy */
  4,   /* field[4] = pages_scanned */
  5,   /* field[5] = pages_skipped_parent */
  6,   /* field[6] = pages_written */
  11,   /* field[11] = shpages_scanned */
  12,   /* field[12] = shpages_skipped_parent */
  13,   /* field[13] = shpages_written */
};
static const ProtobufCIntRange dump_stats_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 14 }
};
const ProtobufCMessageDescriptor dump_stats_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "dump_stats_entry",
  "DumpStatsEntry",
  "DumpStatsEntry",
  "",
  sizeof(DumpStatsEntry),
  14,
  dump_stats_entry__field_descriptors,
  dump_stats_entry__field_indices_by_name,
  1,  dump_stats_entry__number_ranges,
  (ProtobufCMessageInit) dump_stats_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor restore_stats_entry__field_descriptors[5] =
{
  {
    "pages_compared",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(RestoreStatsEntry, pages_compared),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pages_skipped_cow",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(RestoreStatsEntry, pages_skipped_cow),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "forking_time",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(RestoreStatsEntry, forking_time),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "restore_time",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(RestoreStatsEntry, restore_time),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pages_restored",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT64,
    offsetof(RestoreStatsEntry, has_pages_restored),
    offsetof(RestoreStatsEntry, pages_restored),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned restore_stats_entry__field_indices_by_name[] = {
  2,   /* field[2] = forking_time */
  0,   /* field[0] = pages_compared */
  4,   /* field[4] = pages_restored */
  1,   /* field[1] = pages_skipped_cow */
  3,   /* field[3] = restore_time */
};
static const ProtobufCIntRange restore_stats_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor restore_stats_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "restore_stats_entry",
  "RestoreStatsEntry",
  "RestoreStatsEntry",
  "",
  sizeof(RestoreStatsEntry),
  5,
  restore_stats_entry__field_descriptors,
  restore_stats_entry__field_indices_by_name,
  1,  restore_stats_entry__number_ranges,
  (ProtobufCMessageInit) restore_stats_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor stats_entry__field_descriptors[2] =
{
  {
    "dump",
    1,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(StatsEntry, dump),
    &dump_stats_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "restore",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(StatsEntry, restore),
    &restore_stats_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned stats_entry__field_indices_by_name[] = {
  0,   /* field[0] = dump */
  1,   /* field[1] = restore */
};
static const ProtobufCIntRange stats_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor stats_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "stats_entry",
  "StatsEntry",
  "StatsEntry",
  "",
  sizeof(StatsEntry),
  2,
  stats_entry__field_descriptors,
  stats_entry__field_indices_by_name,
  1,  stats_entry__number_ranges,
  (ProtobufCMessageInit) stats_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
