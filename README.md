# Dovehawk.io SMB Exploitation Detection Module

This module detects RPC execution, SMB uploads of executable files, and Responder.py default activity such as LLMNR or NBD exploitation. Capture attacker IP and L2 MAC address.

![Sticker 1](https://dovehawk.io/images/dovehawk_sticker1.png "Sticker 1") ![Sticker 2](https://dovehawk.io/images/dovehawk_sticker2.png "Sticker 2")

## Screencaps

### DoveHawk SMB Activity Reported

![Dovehawk SMB Reports](https://dovehawk.io/images/dovehawk_smb_exec.png "Dovehawk SMB")


### DoveHawk dhsmb.log Local Log

Logs alerts locally.


## Requirements

## Requirements

**Zeek** 3.0 or higher.

**zkg** *zeek package manager*.

**curl** is required for ActiveHTTP requests.


## Database

See [dovehawk_lambda](https://github.com/tylabs/dovehawk_lambda) for an AWS Lambda serverless function to store reporting in RDS Aurora.

## Install

`sudo zkg unbundle dovehawk_smb.bundle`


## Contact

Tyler McLellan [@tylabs](https://twitter.com/tylabs)

