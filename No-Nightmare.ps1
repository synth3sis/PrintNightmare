# -----------------------------------------------------------------
#   Print Nightmare mitigation
# -----------------------------------------------------------------
#   During the exploit stages, the RCE get advantage of the deploy
#   of a malicious DLL inside a spooler's subdirectory. This
#   workaround inhibits SYSTEM's write access to that directory
#   through ACL, making the entire exploit fail
# -----------------------------------------------------------------
#   Il RCE sfrutta nel processo il deploy di una DLL in una
#   sotto-directory dello spooler. Il workaround limita con ACL
#   l'accesso di SYSTEM alla cartella impedendo all'exploit di
#   avere successo

Param (
	[Parameter()][Switch]$Enable,
	[Parameter()][Switch]$Disable,
	[Parameter()][Switch]$Status
)


function Test-Administrator {
	$user = [Security.Principal.WindowsIdentity]::GetCurrent();
	(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}


$lang = Get-WinSystemLocale |Select-Object Name |Select -ExpandProperty Name
If ($lang -eq 'it-IT') {
	$err_adm = "[!] L'esecuzione di questo script richiede i privilegi di amministratore"
	$err_acl = '[!] Non puoi disabilitare e riattivare contemporaneamente la ACL'
	$suc_pcu = '[+] Patch attivata con successo'
	$suc_pcd = '[+] Patch DISattivata con successo'
	$sts_sup = '[>] ACL attivata'
	$sts_sdw = '[<] ACL DISattivata'
} Else {
	$err_adm = "[!] This script requires administrator privileges to run"
	$err_acl = '[!] You cannot enable and disable ACL at the same time'
	$suc_pcu = '[+] Mitigation successfully enabled'
	$suc_pcd = '[+] Mitigation successfully DISabled'
	$sts_sup = '[>] ACL enabled'
	$sts_sdw = '[<] ACL DISabled'
}


If (-not (Test-Administrator)) {
	Write-Host "$err_adm"
	return
}

If (!$Enable -and !$Disable -and !$Status) {
	Write-Host "USAGE:"
	Write-Host "    .\No-Nightmare.ps1 [-Enable -Disable -Status]"
	return
}

If ($Enable -and $Disable) {
	Write-Host "$err_acl"
	Break
}

If ($Enable) {
	$Path = "C:\Windows\System32\spool\drivers"
	$Acl = (Get-Item $Path).GetAccessControl('Access')

	$Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
	$Acl.AddAccessRule($Ar) | Out-Null
	Set-Acl $Path $Acl

	# ----------- VERIFY
	$FixACL = Get-Acl "C:\Windows\System32\spool\drivers"
	$VerifyACL = $FixACL.AccessToString[0..32] -join ''

	If ($VerifyACL -like "*NT AUTHORITY\SYSTEM Deny  Modify*") {
		Write-Host "$suc_pcu"
	} Else {
		Write-Host 'Failed'
	}

	return
}

if ($Disable) {
	$Path = "C:\Windows\System32\spool\drivers"
	$Acl = (Get-Item $Path).GetAccessControl('Access')

	$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
	$Acl.RemoveAccessRule($Ar) | Out-Null
	Set-Acl $Path $Acl

	# ----------- VERIFY
	$FixACL = (Get-Item $Path).GetAccessControl('Access')
	$VerifyACL = $FixACL.AccessToString[0..32] -join ''

	If ($VerifyACL -notlike "*NT AUTHORITY\SYSTEM Deny  Modify*") {
		Write-Host "$suc_pcd"
	} Else {
		Write-Host 'Failed'
	}

	return
}

if ($Status) {
	$Path = "C:\Windows\System32\spool\drivers"
	$Acl = (Get-Item $Path).GetAccessControl('Access')

	$VerifyACL = $ACL.AccessToString[0..32] -join ''

	If ($VerifyACL -like "*NT AUTHORITY\SYSTEM Deny  Modify*") {
		Write-Host "$sts_sup"
	} Else {
		Write-Host "$sts_sdw"
	}
}
