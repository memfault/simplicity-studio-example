# Memfault Simplicity Studio Example

This repo contains a simple example of integrating Memfault with Simplicity Studio, the Gecko SDK (v4.3.1 tested), and Micrium. The application aws written for the EFR32MG24 dev kit. The code was adapted from the example `bt_soc_thermometer_micriumos_mock`. The application contains the following features:

* Reboot reason tracking
* Micrium port integration
* Configurable RAM or Flash-backed coredump storage
* Logging
* Demo CLI to trigger faults, metrics collection, reboots, etc
* Watchdog coredump integration

The source files contained in the Memfault SDK for the SiLabs port can be found at `memfault-firmware-sdk/ports/emlib`

## Integration Code

The source code containing the integration for this example app is located in `<project_root>/memfault`. The file, `memfault_platform_port.c` contains the required functions to integrate this application with the Memfault SDK.

## Demo CLI

The demo CLI component uses Simplicity Studio's built-in CLI configuration. The CLI defaults to using the serial port of the dev kit. To print command info type `mflt` into the console. To add the CLI commands to your project you will need to add a few snippets like the following to your project .slcp file:

```yaml
# In component section
component:
- instance: [example]
  id: cli
```

```yaml
# In template_contribution
template_contribution:
- condition: [cli]
  name: cli_group
  priority: 0
  value: {name: mflt}
- condition: [cli]
  name: cli_group
  priority: 0
  value: {name: test, id: mflt_test_root, group: mflt}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: export, group: mflt, handler: memfault_emlib_cli_export, help: Export
      data as base64 chunks}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: get_core, group: mflt, handler: memfault_emlib_cli_get_core, help: Get
      current coredump state}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: clear_core, group: mflt, handler: memfault_emlib_cli_clear_core, help: Clear
      coredump from storage}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: get_device_info, group: mflt, handler: memfault_emlib_cli_get_device_info,
    help: Read device info structure}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: assert, group: mflt_test_root, handler: memfault_emlib_cli_assert,
    help: Triggers assert to collect a coredump}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: busfault, group: mflt_test_root, handler: memfault_emlib_cli_busfault,
    help: Triggers busfault to collect a coredump}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: hang, group: mflt_test_root, handler: memfault_emlib_cli_hang, help: Triggers
      hang to collect a coredump}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: hardfault, group: mflt_test_root, handler: memfault_emlib_cli_hardfault,
    help: Triggers hardfault to collect a coredump}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: memmanage, group: mflt_test_root, handler: memfault_emlib_cli_memmanage,
    help: Triggers memory management fault to collect a coredump}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: usagefault, group: mflt_test_root, handler: memfault_emlib_cli_usagefault,
    help: Triggers usage fault to collect a coredump}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: reboot, group: mflt_test_root, handler: memfault_emlib_cli_reboot,
    help: Triggers reboot to test reboot reason tracking}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: heartbeat, group: mflt_test_root, handler: memfault_emlib_cli_heartbeat,
    help: Trigger capture of heartbeat metrics}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: logs, group: mflt_test_root, handler: memfault_emlib_cli_logs, help: Writes
      logs to internal buffers}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: log_capture, group: mflt_test_root, handler: memfault_emlib_cli_log_capture,
    help: Serializes current log buffer contents}
- condition: [cli]
  name: cli_command
  priority: 0
  value: {name: trace, group: mflt_test_root, handler: memfault_emlib_cli_trace, help: Captures
      a trace event}
```

The implementations for the CLI command handlers are located in `memfault-firmware-sdk/ports/emlib/cli_demo_commands.c` and `memfault-firmware-sdk/components/demo/`

## Linker File Modifications

The linkerfile autogenerated by Simplicity Studio requires modification to add a region for coredump storage and include the Build ID. This must be added to the linkerfile in your project located at `<project_root>/autogen/linkerfile.ld`. The following snippets should be added:

```
 MEMORY
{
    FLASH   (rx)  : ORIGIN = 0x8012000, LENGTH = 0x16A000
    RAM     (rwx) : ORIGIN = 0x20000000, LENGTH = 0x40000
    // Add line to define coredump region
    COREDUMP_STORAGE_FLASH (rx) : ORIGIN = 0x817C000, LENGTH = 8K
}
```

```
    .note.gnu.build-id : {
        __start_gnu_build_id_start = .;
        KEEP(*(.note.gnu.build-id))
    } > FLASH

    __MemfaultCoreStorageStart = ORIGIN(COREDUMP_STORAGE_FLASH);
    __MemfaultCoreStorageEnd = ORIGIN(COREDUMP_STORAGE_FLASH) + LENGTH(COREDUMP_STORAGE_FLASH);
```

**NOTE:** Simplicity Studio may regenerate this file if components of the project change.