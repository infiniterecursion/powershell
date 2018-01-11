#============================================================================
#
# File: CreateShare.ps1
# 
# Description: This script is designed to assist in the creation of shares
#    on a Windows Server OS with a configured Active Directory environment.
#    This script will go through the task of creating a folder for the share,
#    creating ACL groups in Active Directory, adding the ACL groups to the
#    NTFS permissions for the folder, and sharing the folder with Everyone
#    permissions for the share (NTFS permissions will override this).
#
# Use:
#    This script will need to be called from an elevated Powershell prompt.
#    It accepts two command line parameters outlined below. The script will
#    output some useful information on successful completion. The user running
#    the script will need to have permissions to create a folder in the target
#    location and permissions to add groups to Active Directory. The groups 
#    will be created in the default Users group in Active Directory. The 
#    script will also create a Deny group and set Deny permissions on the share
#    to allow for the possibility of having a Deny All user group that denies
#    access to all shares for members of the group.
#
# Parameters:
#    -rootPath: This is the base path where the new folder will be located.
#        This may work on UNC paths but has not been tested for that.
#        Examples: (C:\share, E:\)
#
#    -path: This is the subdirectory to be created under the rootPath. This
#        is also the name that will be used in the ACL group names and the 
#        name of the share that will be shared out from the server.
#
# Credit: This script is a heavily modified version of an example found
#    here: https://4sysops.com/archives/create-a-new-folder-and-set-permissions-with-powershell/
#    and the author deserves credit for doing most of the heavy-lifting.
#
#============================================================================
param(
[string]$rootPath,
[string]$path
)
Import-Module ActiveDirectory
Import-Module SMBShare
#$rootPath = "C:\test"
#$path = "hello"
$newFolderFull = $rootPath + "\" + $path
Write-Output "New Folder will be: $newFolderFull"
$confirm = Read-Host "Confirm? Y/N"
If(($confirm) -ne "y")
{
# END
}
Else
{
Write-Output "Create AD Groups"
$groupNameRW = "acl_" + $path + "_Write"
$groupNameR = "acl_" + $path + "_Read"
$groupNameF = "acl_" + $path + "_Full"
$groupNameD = "acl_" + $path + "_Deny"
New-AdGroup $groupNameRW -samAccountName $groupNameRW -GroupScope DomainLocal
New-AdGroup $groupNameR -samAccountName $groupNameR -GroupScope DomainLocal
New-AdGroup $groupNameF -samAccountName $groupNameF -GroupScope DomainLocal
New-AdGroup $groupNameD -samAccountName $groupNameD -GroupScope DomainLocal
Write-Output "Add Folder.."
New-Item $newFolderFull -ItemType Directory
Write-Output "Remove Inheritance.."
icacls $newFolderFull /inheritance:d
# Rights
$readOnly = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute"
$readWrite = [System.Security.AccessControl.FileSystemRights]"Modify"
$fullControl = [System.Security.AccessControl.FileSystemRights]"Full"
$DenyAll = [System.Security.AccessControl.FileSystemRights]"Full"
# Inheritance
$inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
# Propagation
$propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
# User
$userRW = New-Object System.Security.Principal.NTAccount($groupNameRW)
$userR = New-Object System.Security.Principal.NTAccount($groupNameR)
$userF = New-Object System.Security.Principal.NTAccount($groupNameF)
$userD = New-Object System.Security.Principal.NTAccount($groupNameD)
# Type
$type = [System.Security.AccessControl.AccessControlType]::Allow
$deny = [System.Security.AccessControl.AccessControlType]::Deny
$accessControlEntryDefault = New-Object System.Security.AccessControl.FileSystemAccessRule @("Domain Users", $readOnly, $inheritanceFlag, $propagationFlag, $type)
$accessControlEntryRW = New-Object System.Security.AccessControl.FileSystemAccessRule @($userRW, $readWrite, $inheritanceFlag, $propagationFlag, $type)
$accessControlEntryR = New-Object System.Security.AccessControl.FileSystemAccessRule @($userR, $readOnly, $inheritanceFlag, $propagationFlag, $type)
$accessControlEntryF = New-Object System.Security.AccessControl.FileSystemAccessRule @($userF, $fullControl, $inheritanceFlag, $propagationFlag, $type)
$accessControlEntryD = New-Object System.Security.AccessControl.FileSystemAccessRule @($userD, $denyAll, $inheritanceFlag, $propagationFlag, $deny)
$objACL = Get-ACL $newFolderFull
$objACL.RemoveAccessRuleAll($accessControlEntryDefault)
$objACL.AddAccessRule($accessControlEntryRW)
$objACL.AddAccessRule($accessControlEntryR)
$objACL.AddAccessRule($accessControlEntryF)
$objACL.AddAccessRule($accessControlEntryD)
Set-ACL $newFolderFull $objACL
Write-Output "Create File Share..."
New-SmbShare -Name $path -Path $newFolderFull -FullAccess "Everyone"
}