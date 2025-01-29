# pyNukiBT
Nuki Bluetooth API

This is only a python API implementation of the Bluetooth communication with Nuki locks and Openers.
It is not intended to be used as a stand alone solution, only as a library that can be used by other solutions (like the [RaspiNukiBridge](https://github.com/ronengr/RaspiNukiBridge) web Nuki-Bridge implementation or the [hass_nuki_bt](https://github.com/ronengr/hass_nuki_bt) Home Assistant component)

## Background
- This is based on [RaspiNukiBridge](https://github.com/dauden1184/RaspiNukiBridge) by [dauden1184](https://github.com/dauden1184/) and [RaspiNukiBridge](https://github.com/regevbr/RaspiNukiBridge) [regevbr](https://github.com/regevbr)
- Nuki documentation
  - [Nuki Smart Lock Bluetooth API 2.3.0](https://developer.nuki.io/uploads/short-url/1qEVXUUpo4xkPvTchbyKbdJLuOV.pdf)
  - [Nuki Opener Bluetooth API 1.1.1](https://developer.nuki.io/uploads/short-url/cVBcHothDOXk16CcI0LwqYTgCy1.pdf)

> Important - if you are experiencing delays using RPI, it is advised to use a bluetooth dongle instead of the builtin bluetooth hardware.
> [TP-LINK UB400](https://www.tp-link.com/us/home-networking/usb-adapter/ub400/) is verified to be working.

> ### Raspberry Pi 3B+ and 4 only
>
> It might be necessary to DOWNGRADE Bluez. [See comment](https://github.com/dauden1184/RaspiNukiBridge/issues/1#issuecomment-1103969957).
>
> ```
> wget http://ftp.hk.debian.org/debian/pool/main/b/bluez/bluez_5.50-1.2~deb10u2_armhf.deb
> sudo apt install ./bluez_5.50-1.2~deb10u2_armhf.deb
> ```
>
> Reboot the Raspberry Pi
