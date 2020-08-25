# Dovehawk.io SMB Exploitation Detection Module

This module detects RPC execution, SMB uploads of executable files, and Responder.py default activity such as LLMNR or NBD exploitation. Capture attacker IP and L2 MAC address. Note that executables are only detected being pushed to a system, not pulled.

This module is intended to detect lateral movement events in corporate environments and credential theft on a local network such as a conference or hotel.

## Getting Started

This module supports reporting events to a central server. It also can be used locally only and will create a new Zeek log named dhsmb.log.

If you are installing from Github, copy config.zeek.orig to config.zeek. To use in local mode, leave this config file unchanged.


![Sticker 1](https://dovehawk.io/images/dovehawk_sticker1.png "Sticker 1") ![Sticker 2](https://dovehawk.io/images/dovehawk_sticker2.png "Sticker 2")


## Screencaps

### DoveHawk SMB/RPC Activity Reported

![Dovehawk SMB Reports](https://dovehawk.io/images/dovehawk_exec.png "Dovehawk SMB")

### Event On Remote Dashboard

![Dovehawk Event](https://dovehawk.io/images/smb_hit.png "Dashboard Hit")




### DoveHawk dhsmb.log Local Log

Logs alerts locally.

![Dovehawk SMB Log](https://dovehawk.io/images/dhsmblog.png "Dashboard Log")

## Requirements

**Zeek** 3.0 or higher.

**zkg** *zeek package manager*.

**curl** is required for ActiveHTTP requests.



## Install

From a bundle:

`sudo zkg unbundle dovehawk_smb.bundle`


From GitHub:

`sudo zkg install https://github.com/tylabs/dovehawk_smb`



## Contact

Tyler McLellan [@tylabs](https://twitter.com/tylabs)

