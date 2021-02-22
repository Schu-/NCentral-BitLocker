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
    3. BitLocker Recovery Keys
```
[BitLocker & N-Central Setup Doc](https://github.com/Schu-/NCentral-BitLocker/tree/main/docs/)

### Task Actions / Script Functions

These are the actions that can currently be performed on a device.

```
1. Encrypt
2. Decrypt
3. Change PW
4. Lock Down Device
```


### Logging

The powershell script is setup to have verbose logging on each run. It does not append its log, but this can be changed by adding -Append. The logs output location is as follows.

```
C:\kits\ncentral\logs\ncentral-bitlocker.txt
```

With v0.80 we have started to write to the Windows Event viewer. You can view log information in the Application log. The application "NCentral-BitLocker" will write during the process of running difrrent tasks. This should help troubleshoot issues if you are having any.

## ToDo

I am looking to implement the following if time permits:

```
1. Better TPM Support
2. User interaction for PIN?
3. More Testing!!!
4. Possibly need some code clean up.
5. Need to add logic if the PIN is blank. Cant encrypt.
```


## Authors

**Andrew Schumacher**
