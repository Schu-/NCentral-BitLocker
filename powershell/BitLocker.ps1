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

.INFO
    Author:  Andrew Schumacher
    GitHub: https://github.com/Schu-

.VERSION
    V0.65
#>

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
} elseif (($bde_status.VolumeStatus -eq 'EncryptionInProgress') -or ($bde_status.VolumeStatus -eq 'DecryptionInProgress')) {
    $global:device_status = 'encrypting-decrpyting'
} elseif ($bde_status.ProtectionStatus -eq 'off' -and $bde_status.VolumeStatus -eq 'FullyDecrypted') {
    $global:device_status = 'not_encrypted'
} else { 
    $global:device_status = 'bitlock_issues'
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
    if ($bde_protect_rcpw -eq $null) {
        #Enable new protector
        Write-Output "Writing new password protector"
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector
        
        #Pull out Password Protector ID 
        $bde_rcid = $bde_protect_rcpw.KeyProtectorID
        
        #Add Protector to AD
        Write-Output "Saving to AD"
        manage-bde -protectors -adbackup $env:SystemDrive -id "$bde_rcid"

    } else {
        #Pull out Password Protector ID 
        $bde_rcid = $bde_protect_rcpw.KeyProtectorID 

        #Add Protector to AD
        Write-Output "Saving to AD"
        manage-bde -protectors -adbackup $env:SystemDrive -id "$bde_rcid"
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

    Write-Output "Rebooting, Success!!"
    $bitlocker_result = "Rebooting, Success!!"
    Shutdown /r /f /t 0
    Exit
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

    Write-Output "Rebooting, Success!!"
    $bitlocker_result = "Rebooting, Success!!"
    Shutdown /r /f /t 0
    Exit
}

function Set-BitLockerDecrypt {
    #Decrypt System
    Write-Output "Decrypting Device"
    Disable-BitLocker -MountPoint $env:SystemDrive

    Write-Output "Decrypting System"
    $bitlocker_result = "Decrypting System"
    Shutdown /r /f /t 0
    Exit
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
    #Try to change Password
    Set-BitLockerPWChange  
} else {
    #Task Not Set
    Write-Output "Encryption task not set. Confirm OFF is not set in Nable"
    $bitlocker_result = "Encryption task not set. Confirm OFF is not set in Nable"
    $bitlocker_status = $global:device_status
    Exit 1
}
##SCRIPT END##
