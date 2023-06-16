//! @file
//!
//! @brief
//! A port for the platform dependencies needed to use the coredump feature from the "panics"
//! component by saving the Memfault coredump data in a "noinit" region of RAM.
//!
//! This can be linked in directly by adding the .c file to the build system or can be
//! copied into your repo and modified to collect different RAM regions.
//!
//! By default, it will collect the top of the stack which was running at the time of the
//! crash. This allows for a reasonable backtrace to be collected while using very little RAM.
//!
//! Place the "noinit" region in an area of RAM that will persist across bootup.
//!    The region must:
//!    - not be placed in .bss
//!    - not be an area of RAM used by any of your bootloaders
//!    For example, with GNU GCC, this can be achieved by adding something like the following to
//!    your linker script:
//!    MEMORY
//!    {
//!      [...]
//!      COREDUMP_NOINIT (rw) :  ORIGIN = <RAM_REGION_START>, LENGTH = 1024
//!    }
//!    SECTIONS
//!    {
//!      [...]
//!      .coredump_noinit (NOLOAD): { KEEP(*(*.noinit.mflt_coredump)) } > COREDUMP_NOINIT
//!    }

#include "memfault/components.h"
#include "memfault/ports/reboot_reason.h"
#include "em_device.h"
#include "app_log.h"
#include <cpu/include/cpu.h>

#if MEMFAULT_PLATFORM_COREDUMP_STORAGE_USE_RAM

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

MEMFAULT_PUT_IN_SECTION(".mflt_reboot_tracking.noinit")
static uint8_t s_reboot_tracking[MEMFAULT_REBOOT_TRACKING_REGION_SIZE];

#if !MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_CUSTOM

#if ((MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_SIZE % 4) != 0)
#error "MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_SIZE must be a multiple of 4"
#endif

MEMFAULT_STATIC_ASSERT(sizeof(uint32_t) == 4, "port expects sizeof(uint32_t) == 4");

MEMFAULT_PUT_IN_SECTION(MEMFAULT_PLATFORM_COREDUMP_NOINIT_SECTION_NAME)
static uint32_t s_ram_backed_coredump_region[MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_SIZE / 4];

#define MEMFAULT_PLATFORM_COREDUMP_RAM_START_ADDR ((uint8_t *)&s_ram_backed_coredump_region[0])

#endif /* MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_CUSTOM */

#if !MEMFAULT_PLATFORM_COREDUMP_STORAGE_REGIONS_CUSTOM
//! Collect the active stack as part of the coredump capture.
//! User can implement their own version to override the implementation
MEMFAULT_WEAK
const sMfltCoredumpRegion *memfault_platform_coredump_get_regions(
    const sCoredumpCrashInfo *crash_info, size_t *num_regions)
{
  static sMfltCoredumpRegion s_coredump_regions[1];

  const size_t stack_size = memfault_platform_sanitize_address_range(
      crash_info->stack_address, MEMFAULT_PLATFORM_ACTIVE_STACK_SIZE_TO_COLLECT);

  s_coredump_regions[0] = MEMFAULT_COREDUMP_MEMORY_REGION_INIT(
      crash_info->stack_address, stack_size);
  *num_regions = MEMFAULT_ARRAY_SIZE(s_coredump_regions);
  return &s_coredump_regions[0];
}
#endif

void memfault_platform_coredump_storage_get_info(sMfltCoredumpStorageInfo *info)
{
  *info = (sMfltCoredumpStorageInfo){
      .size = MEMFAULT_PLATFORM_COREDUMP_STORAGE_RAM_SIZE,
  };
}

static bool prv_op_within_flash_bounds(uint32_t offset, size_t data_len)
{
  sMfltCoredumpStorageInfo info = {0};
  memfault_platform_coredump_storage_get_info(&info);
  return (offset + data_len) <= info.size;
}

bool memfault_platform_coredump_storage_read(uint32_t offset, void *data,
                                             size_t read_len)
{
  if (!prv_op_within_flash_bounds(offset, read_len))
  {
    return false;
  }

  const uint8_t *storage_ptr = MEMFAULT_PLATFORM_COREDUMP_RAM_START_ADDR;
  const uint8_t *read_ptr = &storage_ptr[offset];
  memcpy(data, read_ptr, read_len);
  return true;
}

bool memfault_platform_coredump_storage_erase(uint32_t offset, size_t erase_size)
{
  if (!prv_op_within_flash_bounds(offset, erase_size))
  {
    return false;
  }

  uint8_t *storage_ptr = MEMFAULT_PLATFORM_COREDUMP_RAM_START_ADDR;
  void *erase_ptr = &storage_ptr[offset];
  memset(erase_ptr, 0x0, erase_size);
  return true;
}

bool memfault_platform_coredump_storage_write(uint32_t offset, const void *data,
                                              size_t data_len)
{
  if (!prv_op_within_flash_bounds(offset, data_len))
  {
    return false;
  }

  uint8_t *storage_ptr = MEMFAULT_PLATFORM_COREDUMP_RAM_START_ADDR;
  uint8_t *write_ptr = (uint8_t *)&storage_ptr[offset];
  memcpy(write_ptr, data, data_len);
  return true;
}

void memfault_platform_coredump_storage_clear(void)
{
  const uint8_t clear_byte = 0x0;
  memfault_platform_coredump_storage_write(0, &clear_byte, sizeof(clear_byte));
}

#endif /* MEMFAULT_PLATFORM_COREDUMP_STORAGE_USE_RAM */

void memfault_platform_get_device_info(sMemfaultDeviceInfo *info)
{
  // !FIXME: Populate with platform device information

  // IMPORTANT: All strings returned in info must be constant
  // or static as they will be used _after_ the function returns

  // See https://mflt.io/version-nomenclature for more context
  *info = (sMemfaultDeviceInfo){
      // An ID that uniquely identifies the device in your fleet
      // (i.e serial number, mac addr, chip id, etc)
      // Regular expression defining valid device serials: ^[-a-zA-Z0-9_]+$
      .device_serial = "DEMOSERIAL",
      // A name to represent the firmware running on the MCU.
      // (i.e "ble-fw", "main-fw", or a codename for your project)
      .software_type = "app-fw",
      // The version of the "software_type" currently running.
      // "software_type" + "software_version" must uniquely represent
      // a single binary
      .software_version = "1.0.0",
      // The revision of hardware for the device. This value must remain
      // the same for a unique device.
      // (i.e evt, dvt, pvt, or rev1, rev2, etc)
      // Regular expression defining valid hardware versions: ^[-a-zA-Z0-9_\.\+]+$
      .hardware_version = "dvt1",
  };
}

//! Last function called after a coredump is saved. Should perform
//! any final cleanup and then reset the device
void memfault_platform_reboot(void)
{
  NVIC_SystemReset();
  while (1)
  {
  } // unreachable
}

bool memfault_platform_time_get_current(sMemfaultCurrentTime *time)
{
  (void)time;
  return false;
}

size_t memfault_platform_sanitize_address_range(void *start_addr, size_t desired_size)
{
  static const struct
  {
    uint32_t start_addr;
    size_t length;
  } s_mcu_mem_regions[] = {
      {.start_addr = 0x20000000, .length = 0x40000},
  };

  for (size_t i = 0; i < MEMFAULT_ARRAY_SIZE(s_mcu_mem_regions); i++)
  {
    const uint32_t lower_addr = s_mcu_mem_regions[i].start_addr;
    const uint32_t upper_addr = lower_addr + s_mcu_mem_regions[i].length;
    if ((uint32_t)start_addr >= lower_addr && ((uint32_t)start_addr < upper_addr))
    {
      return MEMFAULT_MIN(desired_size, upper_addr - (uint32_t)start_addr);
    }
  }

  return 0;
}

void memfault_platform_log(eMemfaultPlatformLogLevel level, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  char log_buf[128];
  vsnprintf(log_buf, sizeof(log_buf), fmt, args);

  const char *lvl_str;
  switch (level)
  {
  case kMemfaultPlatformLogLevel_Debug:
    lvl_str = "D";
    break;

  case kMemfaultPlatformLogLevel_Info:
    lvl_str = "I";
    break;

  case kMemfaultPlatformLogLevel_Warning:
    lvl_str = "W";
    break;

  case kMemfaultPlatformLogLevel_Error:
    lvl_str = "E";
    break;

  default:
    lvl_str = "D";
    break;
  }

  vsnprintf(log_buf, sizeof(log_buf), fmt, args);

  printf("[%s] MFLT: %s\n", lvl_str, log_buf);
}

void memfault_platform_log_raw(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vprintf(fmt, args);
  printf("\n");

  va_end(args);
}

uint64_t memfault_platform_get_time_since_boot_ms(void)
{
  CPU_TS32 timestamp;
  CPU_INT64U usecs;
  timestamp = CPU_TS_Get32();
  usecs = CPU_TS32_to_uSec(timestamp);
  return usecs / 1000;
}

void memfault_platform_reboot_tracking_boot(void)
{
  sResetBootupInfo reset_info = {0};
  memfault_reboot_reason_get(&reset_info);
  memfault_reboot_tracking_boot(s_reboot_tracking, &reset_info);
}

//! !FIXME: This function _must_ be called by your main() routine prior
//! to starting an RTOS or baremetal loop.
int memfault_platform_boot(void)
{
  // !FIXME: Add init to any platform specific ports here.
  // (This will be done in later steps in the getting started Guide)

  memfault_build_info_dump();
  memfault_device_info_dump();
  memfault_platform_reboot_tracking_boot();

  // initialize the event storage buffer
  static uint8_t s_event_storage[1024];
  const sMemfaultEventStorageImpl *evt_storage =
      memfault_events_storage_boot(s_event_storage, sizeof(s_event_storage));

  // configure trace events to store into the buffer
  memfault_trace_event_boot(evt_storage);

  // record the current reboot reason
  memfault_reboot_tracking_collect_reset_info(evt_storage);

  // configure the metrics component to store into the buffer
  //  sMemfaultMetricBootInfo boot_info = {
  //      .unexpected_reboot_count = memfault_reboot_tracking_get_crash_count(),
  //  };
  //  memfault_metrics_boot(evt_storage, &boot_info);

  MEMFAULT_LOG_INFO("Memfault Initialized!");

  return 0;
}
