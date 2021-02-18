# NCentral-BitLocker

This script was created to work in combination with N-Central's Automation Manager & BitLocker for AD. The script also uses some Custom Properies that need to be setup on the N-Central server and selected on the device we will be encrypting. 

Once all is setup, you will create a scheduled task using the AMP file. This task will then check the device, send the recovery password generated to AD, and perform the action setup in the N-Central Custom Properties.

## Getting Started

More info to come soon.

### Prerequisites

The following will need to be setup to make everything work as expdcted. (More info to come)

```
1. Server / AD Setup
    1. BitLocker GPO
2. N-Central Server Setup
    1. Custom Properties
```

### Task Actions / Script Functions

These are the actions that can currently be performed on a device.

```
1. Encrypt
2. Decrypt
3. Change PW
```


### Logging

The powershell script is setup to have verbose logging on each run. It does not append its log, but this can be changed by adding -Append. The logs output location is as follows.

```
C:\kits\ncentral\logs\ncentral-bitlocker.txt
```

## ToDo

I am looking to implement the following if time permits:

```
1. Secure Device Function (Cause BitLocker Recovery)
2. Better TPM Support
3. More Testing!!!
```


## Authors

**Andrew Schumacher**
