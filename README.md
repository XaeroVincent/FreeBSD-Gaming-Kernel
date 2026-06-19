## Custom gaming-focused FreeBSD kernels with the following patches:

**AI Disclosure:** _AI agents were used to assist with development._

* **Syscall User Dispatch** - to support games with aggressive anti-tamper DRM, such as Denuvo
* **Linsysfs nodes** - to enable GPU accelerated Linux applications with Mesa graphics
* **Hidraw ioctl handler** - to improve game controller support **(Currently Incomplete)**
* **Ignore EPOLLEXCLUSIVE** - to paritally workaround games and apps that require EPOLLEXCLUSIVE

Used FreeBSD Source Code:
https://github.com/freebsd/freebsd-src/tree/release/15.1.0
