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
    bitlocker_result
    bitlocker_status
    Windows Event Log (Application Log / NCentral-BitLocker)

.INFO
    Author:  Andrew Schumacher
    GitHub: https://github.com/Schu-/NCentral-BitLocker

.VERSION
    V0.80
#>
#Start Verbose Logging#
Start-Transcript -Path "C:\kits\ncentral\logs\ncentral-bitlocker.txt"

#Setup Windows Logging
$winlogsource = [System.Diagnostics.EventLog]::SourceExists("NCentral-Bitlocker")
if ($winlogsource -eq "False") {
    New-EventLog –LogName "Application" –Source “NCentral-BitLocker”
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1000 -EntryType Information -Message "NCentral-BitLocker is starting... Device did not have EventLog source NCentral-BitLocker."
} else {
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1001 -EntryType Information -Message "NCentral-BitLocker is starting... Device has EventLog source NCentral-BitLocker."
}

##Variables START##

#Define Script Variables
$global:device_status = $null
$global:bde_pctpm_status = $null
$global:bitlocker_pw = $null
$global:bde_protector = $null

##Variables END##

##FUNCTIONS START##

function Get-BitLockerStatus {
    #Check BitLocker Status
$bde_status = Get-Bitlockervolume
if ($bde_status.ProtectionStatus -eq 'on' -and $bde_status.VolumeStatus -eq 'FullyEncrypted') {
    $global:device_status = 'encrypted'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1020 -EntryType Information -Message "Device is Encrypted."
} elseif (($bde_status.VolumeStatus -eq 'EncryptionInProgress') -or ($bde_status.VolumeStatus -eq 'DecryptionInProgress')) {
    $global:device_status = 'encrypting-decrpyting'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1020 -EntryType Warning -Message "Device is Encrypting or Decrypting."
} elseif ($bde_status.ProtectionStatus -eq 'off' -and $bde_status.VolumeStatus -eq 'FullyDecrypted') {
    $global:device_status = 'not_encrypted'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1020 -EntryType Information -Message "Device is not Encrypted."
} else { 
    $global:device_status = 'bitlock_issues'
    Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1020 -EntryType Error -Message "Device is in an odd BitLocker State. Please check BitLocker status with manage-bde -status command. "
    exit 1
}
}

function Get-PCTPM {
    #Get PC's TPM Status
    $bde_pctpm = Get-Tpm
    if ($bde_pctpm.TpmPresent -eq "Ture" -and $bde_pctpm.TpmReady -eq "True" -and $bde_pctpm.TpmEnabled -eq "True" ) {
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
        
        #Pull out Password Protector ID 
        $bde_rcid = $bde_protect_rcpw.KeyProtectorID
        
        #Add Protector to AD
        Write-Output "Saving to AD"
        manage-bde -protectors -adbackup $env:SystemDrive -id "$bde_rcid"
       
        #Confirm Protector Saved
        if ($lastexitcode -ne '0') {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1010 -EntryType Error -Message "Device Recovery Key failed to save to AD."
            exit 1
        } else {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1015 -EntryType Information -Message "Device Recovery Key saved correctly to AD."
        }
    } else {
        #Pull out Password Protector ID 
        $bde_rcid = $bde_protect_rcpw.KeyProtectorID 

        #Add Protector to AD
        Write-Output "Saving to AD"
        manage-bde -protectors -adbackup $env:SystemDrive -id "$bde_rcid"

        #Confirm Protector Saved
        if ($lastexitcode -ne '0') {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1010 -EntryType Error -Message "Device Recovery Key failed to save to AD."
            exit 1
        } else {
            Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1015 -EntryType Information -Message "Device Recovery Key saved correctly to AD."
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
    Enable-BitLocker -MountPoint $env:SystemDrive -PasswordProtector $global:bitlocker_pw

    #Confirm Encryption Sucess
    if ($lastexitcode -ne '0') {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1025 -EntryType Error -Message "Device Encryption failed. Please run manage-bde -status to get a status of devices BitLocker."
        exit 1
    } else {
        Write-Output "Rebooting, Success!!"
        $bitlocker_result = "Rebooting, Success!!"
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1025 -EntryType Information -Message "Device Encryption enabled correctly. Rebooting & Starting Encryption."
        Shutdown /r /f /t 0
        Exit    
        }    

}

function Set-BitLockerPWChange {
    #Protector Checking, Creation & add to AD
    Get-BitLockerProtector

    #Find Password Protector & Pruge
    Write-Output "Attempting Protector Removal..."
    $bde_protect_pw = $global:bde_protector.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Password' }
    $bde_pwid = $bde_protect_pw.KeyProtectorID
    Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $bde_pwid

    #Add/Update Password
    Write-Output "Attempting Protector Addition..."
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -PasswordProtector $global:bitlocker_pw

    #Confirm Password Change Success
    if ($lastexitcode -ne '0') {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1030 -EntryType Error -Message "Device Encryption password failed to change. Please run manage-bde -status to get a status of devices BitLocker."
        exit 1
    } else {
        Write-Output "Rebooting, Success!!"
        $bitlocker_result = "Rebooting, Success!!"
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1030 -EntryType Information -Message "Device Encryption password changed correctly. Rebooting device to confirm."
        Shutdown /r /f /t 0
        Exit    
        }    
}

function Set-BitLockerDecrypt {
    #Decrypt System
    Write-Output "Decrypting Device"
    Disable-BitLocker -MountPoint $env:SystemDrive

    #Confirm Decryption Success
    if ($lastexitcode -ne '0') {
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1035 -EntryType Error -Message "Device Decryption failed. Please run manage-bde -status to get a status of devices BitLocker."
        exit 1
    } else {
        Write-Output "Decrypting System"
        $bitlocker_result = "Decrypting System"
        Write-EventLog -LogName "Application" -Source “NCentral-BitLocker” -EventID 1035 -EntryType Information -Message "Device Decryption started. Rebooting device to confirm."
        Shutdown /r /f /t 0
        Exit    
        }  
}

##FUNCTIONS END##



##SCRIPT START##

#Convert Custom Properties String
$global:bitlocker_pw = ConvertTo-SecureString $bitlocker_pin -AsPlainText -Force


#Check BitLocker & TPM Status
Get-BitLockerStatus
Get-PCTPM


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
} else {
    #Task Not Set
    Write-Output "Encryption task not set. Confirm OFF is not set in Nable"
    $bitlocker_result = "Encryption task not set. Confirm OFF is not set in Nable"
    $bitlocker_status = $global:device_status
    Exit 1
}
##SCRIPT END##