# NCentral-BitLocker

This script was created to work in combination with N-Central's Automation Manager & BitLocker for AD. The script also uses some Custom Properies that need to be setup on the N-Central server and selected on the device we will be encrypting. 

Once all is setup, you will create a scheduled task using the AMP file. This task will then check the device, send the recovery password generated to AD, and perform the action setup in the N-Central Custom Properties.

## Getting Started

### Prerequisites

To get this to working correctly the following must be setup. Feel free to review the BitLocker & N-Central Setup document for info on how to setup these things.

```
1. N-Central Server Setup
    1. N-Central Custom Properties Creation
    2. Setting BitLocker propeties per device
    3. Creating BitLocker Encryption Task
2. Customer Setup
    1. BitLocker Mangement Tools Install
    2. Group Policy Creation
    3. BitLocker Recovery Key Verification
```
[BitLocker & N-Central Setup Doc](https://github.com/Schu-/NCentral-BitLocker/blob/main/docs/BitLocker%20%26%20N-Central%20Setup.pdf)

### Task Actions / Script Functions

These are the actions that can currently be performed on a device.

```
1. Encrypt w/ PIN (TPM PIN Support in BETA)
2. Decrypt
3. Change PIN
4. Lock Down Device
```


### Logging
With v0.80 we have started to write to the Windows Event viewer. You can view log information in the Application log. The application "NCentral-BitLocker" will write during the process of running difrrent tasks. This should help troubleshoot issues if you are having any.


Starting with v1.0 we have disabled by default the Transcript Logging. The Encryption Recovery Key prints in this log and this is insecure.

```
C:\kits\ncentral\logs\ncentral-bitlocker.txt
```


## ToDo

Here are some things I would like to implement if I am able to get the time:

```
1. Advanced TPM Support & More Options
2. Support for user interaction?
```


## Authors

**Andrew Schumacher**
