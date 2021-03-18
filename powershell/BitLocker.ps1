<#
.DESCRIPTION
    This script will pull the Nable custom property's for PIN and encrypt task. 
    Once the data as been pulled into the script, it will perform the associated
    task on the workstation. An Nable automation policy will need to be created 
    so everything can be run on the workstation correctly.

.INPUTS
    bitlocker_pin 
    bitlocker_task

.OUTPUTS
    Windows Event Log (Application Log / NCentral-BitLocker)

.INFO
    Author:  Andrew Schumacher
    GitHub: https://github.com/Schu-/NCentral-BitLocker

.VERSION
    V1.0
#>
#Start Transcript Logging# Warning: The Encryption Recovery Key will print in this log. This is Insecure!!
#Start-Transcript -Path "C:\kits\ncentral\logs\ncentral-bitlocker.txt"

#Setup Windows Logging
$winlogsource = [System.Diagnostics.EventLog]::SourceExists("NCentral-Bitlocker")
if ($winlogsource -eq $false) {
    New-EventLog –LogName "Application" –Source “NCentral-BitLocker”
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3000 -EntryType Information -Message "NCentral-BitLocker is starting..."
} else {
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3001 -EntryType Information -Message "NCentral-BitLocker is starting..."
}

##Variables START##

#Define Script Variables
$global:device_status = $null
$global:bde_pctpm_status = $null
$global:bitlocker_pw = $null
$global:bde_protector = $null

##Variables END##


##FUNCTIONS START##

function Get-BitLockerPass {
    #Check PIN/Password
if (($bitlocker_task -eq "encrypt") -or ($bitlocker_task -eq "change pin") -and $null -eq $bitlocker_pin) {
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3005 -EntryType Error -Message "BitLocker PIN/Password Blank & Task Set to Encrypt. FAIL!" 
    exit 1 
} elseif (($bitlocker_task -eq "encrypt") -or ($bitlocker_task -eq "change pin") -and $null -ne $bitlocker_pin) {
    if (($bitlocker_pin -cmatch '[a-z]') -and ($bitlocker_pin -cmatch '[A-Z]') -and ($bitlocker_pin -match '\d') -and ($bitlocker_pin.length -ge 8) -and ($bitlocker_pin -match '!|@|#|%|^|&|$')) {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3007 -EntryType Information -Message "Strong Password Entered. Securing Password." 
        $global:bitlocker_pw = ConvertTo-SecureString $bitlocker_pin -AsPlainText -Force 
    } else {
        if ($bitlocker_pin.length -ge 8) {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3007 -EntryType Warning -Message "Weak Password Entered. Securing Password." 
            $global:bitlocker_pw = ConvertTo-SecureString $bitlocker_pin -AsPlainText -Force
        } else {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3007 -EntryType Error -Message "Password does not meet minimum requirements. FAIL!" 
            exit 1
        }

    }
} else {
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3007 -EntryType Information -Message "Task: $bitlocker_task | Device Status: $global:device_status | PIN/Password Not Required"
}
}

function Get-BitLockerStatus {
    #Check BitLocker Status
$bde_status = Get-Bitlockervolume
if ($bde_status.ProtectionStatus -eq 'on' -and $bde_status.VolumeStatus -eq 'FullyEncrypted') {
    $global:device_status = 'encrypted'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3020 -EntryType Information -Message "Device is Encrypted."
} elseif (($bde_status.VolumeStatus -eq 'EncryptionInProgress') -or ($bde_status.VolumeStatus -eq 'DecryptionInProgress')) {
    $global:device_status = 'encrypting-decrpyting'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3020 -EntryType Warning -Message "Device is Encrypting or Decrypting."
} elseif ($bde_status.ProtectionStatus -eq 'off' -and $bde_status.VolumeStatus -eq 'FullyDecrypted') {
    $global:device_status = 'not_encrypted'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3020 -EntryType Information -Message "Device is not Encrypted."
} else { 
    $global:device_status = 'bitlock_issues'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3020 -EntryType Error -Message "Device is in an odd BitLocker State. Please check BitLocker status with manage-bde -status command. "
    exit 1
}
}

function Get-PCTPM {
    #Get PC's TPM Status
    $bde_pctpm = Get-Tpm
    if ($bde_pctpm.TpmPresent -eq "True" -and $bde_pctpm.TpmReady -eq "True" -and $bde_pctpm.TpmEnabled -eq "True" ) {
        $global:bde_pctpm_status = "ready"
    } else {
        $global:bde_pctpm_status = "not_ready"
    }
}

function Get-BitLockerProtector {
    #Check for a Recovery Password
    $global:bde_protector = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $bde_protect_rcpw = $global:bde_protector.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    if ($null -eq $bde_protect_rcpw) {
        #Enable new protector
        Write-Output "Writing new password protector"
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector
        
        #Check for a Recovery Password
        $global:bde_protector = Get-BitLockerVolume -MountPoint $env:SystemDrive
        $bde_protect_rcpw = $global:bde_protector.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

        #Pull out Password Protector ID
        $bde_rcid = $bde_protect_rcpw.KeyProtectorID
        
        #Add Protector to AD
        Write-Output "Saving to AD"
        manage-bde -protectors -adbackup $env:SystemDrive -id "$bde_rcid"

        #Confirm Protector Saved
        if ($lastexitcode -ne '0') {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3010 -EntryType Error -Message "Device Recovery Key failed to save to AD."
            exit 1
        } else {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3015 -EntryType Information -Message "Device Recovery Key saved correctly to AD."
        }
    } else {
        #Pull out Password Protector ID 
        $bde_rcid = $bde_protect_rcpw.KeyProtectorID 

        #Add Protector to AD
        Write-Output "Saving to AD"
        manage-bde -protectors -adbackup $env:SystemDrive -id "$bde_rcid"

        #Confirm Protector Saved
        if ($lastexitcode -ne '0') {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3010 -EntryType Error -Message "Device Recovery Key failed to save to AD."
            exit 1
        } else {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3015 -EntryType Information -Message "Device Recovery Key saved correctly to AD."
        }
    }        
}

function Set-BitLockerProtectorDelete {
    #Delete any protectors
    Write-Output "Deleting old password protectors"
    manage-bde -protectors -delete $env:SystemDrive
}

function Set-BitLockerEncrypt {
    #Protector Checking, Creation & add to AD
    Get-BitLockerProtector
    
    #Encrypt
    Write-Output "Attempting Encrypt..."
    if ($global:bde_pctpm_status -eq "ready") {
        Enable-BitLocker -MountPoint $env:SystemDrive -TpmAndPinProtector $global:bitlocker_pw
    } else {
        Enable-BitLocker -MountPoint $env:SystemDrive -PasswordProtector $global:bitlocker_pw
    }    


    #Confirm Encryption Sucess
    if ($lastexitcode -ne '0') {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3025 -EntryType Error -Message "Device Encryption failed. Please run manage-bde -status to get a status of devices BitLocker."
        exit 1
    } else {
        Write-Output "Rebooting, Success!!"
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3025 -EntryType Information -Message "Device Encryption enabled correctly. Rebooting & Starting Encryption."
        Shutdown /r /f /t 0
        Exit    
        }    
}

function Set-BitLockerPWChange {
    #Protector Checking, Creation & add to AD
    Get-BitLockerProtector

    #Find Password Protector & Pruge
    Write-Output "Attempting Protector Removal..."
    if ($global:bde_pctpm_status -eq "ready") {
        $bde_protect_pw = $global:bde_protector.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'TpmAndPinProtector' }
        $bde_pwid = $bde_protect_pw.KeyProtectorID
        Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $bde_pwid
    } else {
        $bde_protect_pw = $global:bde_protector.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Password' }
        $bde_pwid = $bde_protect_pw.KeyProtectorID
        Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $bde_pwid
    }

    #Add/Update Password
    Write-Output "Attempting Protector Addition..."
    if ($global:bde_pctpm_status -eq "ready") {
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector $global:bitlocker_pw
    } else {
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -PasswordProtector $global:bitlocker_pw
    } 

    #Confirm Password Change Success
    if ($lastexitcode -ne '0') {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3030 -EntryType Error -Message "Device Encryption password failed to change. Please run manage-bde -status to get a status of devices BitLocker."
        exit 1
    } else {
        Write-Output "Rebooting, Success!!"
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3030 -EntryType Information -Message "Device Encryption password changed correctly. Rebooting device to confirm."
        Shutdown /r /f /t 0
        Exit    
        }  
}

function Set-BitLockerDecrypt {
    #Decrypt System
    Write-Output "Decrypting Device"
    Disable-BitLocker -MountPoint $env:SystemDrive

    #Delete Protectors
    Set-BitLockerProtectorDelete

    #Confirm Decryption Success
    $bde_status = Get-Bitlockervolume
    if ($bde_status.VolumeStatus -eq 'DecryptionInProgress') {
        Write-Output "Decrypting System"
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3035 -EntryType Information -Message "Device Decryption started. Rebooting device to confirm."
        Shutdown /r /f /t 0
        Exit        
    } else {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3035 -EntryType Error -Message "Device Decryption failed. Please run manage-bde -status to get a status of devices BitLocker."
        exit 1    
        } 
}

function Set-BitLockerSecured {
    #Check for a Recovery Protectors
    $global:bde_protector = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $bde_recoverykeys = $global:bde_protector.KeyProtector | Where-Object { $_.KeyProtectorType -ne 'RecoveryPassword' }
    foreach ($bde_rckeys in $bde_recoverykeys) {
        #Pull out Password Protector ID
        $rckey_id = $bde_rckeys.KeyProtectorID

        #Delete Recovery Key
        Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $rckey_id
    }
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3045 -EntryType Warning -Message "Device Protectors Deleted. Device in Recovery Mode."
    shutdown /r /f /t 0    
}

##FUNCTIONS END##



##SCRIPT START##


#Check BitLocker & TPM Status
Get-BitLockerStatus
Get-PCTPM

#Check BitLocker PIN/Password
Get-BitLockerPass


#Confirm BitLocker Task & Proceed
if ($bitlocker_task -eq "encrypt" -and $global:device_status -eq "not_encrypted") {
    #Try to Encrypt
    Set-BitLockerEncrypt  
} elseif ($bitlocker_task -eq "decrypt" -and $global:device_status -eq "encrypted") {
    #Try to Decrypt
    Set-BitLockerDecrypt  
} elseif ($bitlocker_task -eq "change pin" -and $global:device_status -eq "encrypted") {
    #Try to Change Password
    Set-BitLockerPWChange  
} elseif ($bitlocker_task -eq "lock device" -and $global:device_status -eq "encrypted") { 
    #Try to Lock Device
    Set-BitLockerSecured
}else {
    #Issues & Task did not run
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 3035 -EntryType Error -Message "Task: $bitlocker_task | Device Status: $global:device_status | FAILED!  "
    exit 1
}
##SCRIPT END##