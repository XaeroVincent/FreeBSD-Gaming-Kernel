## Custom gaming-focused FreeBSD kernels with the following patches:
* **Linsysfs nodes** - to enable GPU accelerated Linux applications with Mesa graphics
* **Hidraw ioctl handler** - to improve game controller support **(Currently Incomplete)**
* **Ignore EPOLLEXCLUSIVE** - to workaround games that require it such as Dota 2 and Counter-Strike 2

These patches were created primarily by: **[Alex S (shkhln)](https://github.com/shkhln)**

Used FreeBSD Source Code:
https://github.com/freebsd/freebsd-src/tree/release/15.0.0-p2
