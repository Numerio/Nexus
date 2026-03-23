# nexus

Nexus is a set of Linux kernel modules that bridge the Linux kernel with the BeOS/Haiku userspace runtime. It is a core component of [VitruvianOS](https://github.com/VitruvianOS/Vitruvian), included as a submodule.

## Overview

BeOS and Haiku expose kernel APIs with no direct equivalent in Linux — IPC ports, named semaphores, shared memory areas, a thread messaging model, and filesystem event notifications. Nexus implements these as thin kernel modules on top of the standard Linux kernel, exposing them to userspace through character devices and `ioctl` interfaces.

## Modules

### nexus (`/dev/nexus`)

Main IPC module. Implements the BeOS/Haiku kernel primitives used by the messaging subsystem:

- **Ports** — bounded message queues identified by integer ID or name; supports blocking read/write with timeouts
- **Threads** — per-thread send/receive channels with spawn, resume, waitfor, and exit lifecycle operations
- **Semaphores** — counting semaphores with acquire/release and timeout support
- **Areas** — named shared memory regions with protection control and cross-team transfer

Each process that opens `/dev/nexus` gets its own `nexus_team` context. Teams and threads are tracked in kernel memory and cleaned up automatically on release.

### node_monitor

Filesystem event notifications implementing the BeOS `node_monitor` API on top of Linux's `fsnotify` subsystem. Translates kernel filesystem events into BeOS-compatible messages delivered to registered userspace listeners:

- `B_ENTRY_CREATED` / `B_ENTRY_REMOVED` / `B_ENTRY_MOVED`
- `B_STAT_CHANGED` / `B_ATTR_CHANGED`
- `B_DEVICE_MOUNTED` / `B_DEVICE_UNMOUNTED`

## Repository structure

```
nexus/          kernel module source (area.c, nexus.c, vref.c, node_monitor.c, ...)
debian/         packaging for nexus-dkms Debian package
nexus.conf      modules-load.d config (loads nexus + nexus_vref at boot)
CMakeLists.txt  integration with the VitruvianOS build system
```

## Distribution

Nexus is distributed as `nexus-dkms`, a DKMS Debian package that compiles and installs the modules against the target kernel on the live image. It is built automatically as part of the VitruvianOS `.deb` and ISO build pipeline.

## Building

### As part of VitruvianOS

Nexus is built automatically. See the [VitruvianOS build instructions](https://wiki.v-os.dev/docs/getting-started/building/).

### Standalone

Requires kernel headers for the running kernel:

```sh
make -C /lib/modules/$(uname -r)/build M=$(pwd)/nexus modules
```

Load manually:

```sh
sudo insmod nexus/nexus.ko
sudo insmod nexus/nexus_vref.ko
```

Or install and load via DKMS/modules-load:

```sh
sudo cp nexus.conf /etc/modules-load.d/
```

## License

GPL-2.0. Copyright (C) 2022–2026 Dario Casalinuovo.
