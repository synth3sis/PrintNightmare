# -----------------------------------------------------------------
# Print nightmare workaround
# -----------------------------------------------------------------
#   Il RCE sfrutta nel processo il deploy di una DLL in una
#   sotto-directory dello spooler. Il workaround limita da
#   ACL l'accesso di SYSTEM alla cartella impedendone la scrittura

Param (
	[Parameter()][Switch]$Enable,
	[Parameter()][Switch]$Disable,
	[Parameter()][Switch]$Status
)

If (!$Enable -and !$Disable -and !$Status) {
	Write-Host "USAGE:"
	Write-Host "    .\No-Nightmare.ps1 [-Enable -Disable -Status]"
	return
}

If ($Enable -and $Disable) {
	Write-Host "[!] Non puoi disabilitare e riattivare contemporaneamente la ACL"
	Break
}

If ($Enable) {
	$Path = "C:\Windows\System32\spool\drivers"
	$Acl = (Get-Item $Path).GetAccessControl('Access')

	$Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
	$Acl.AddAccessRule($Ar) | Out-Null
	Set-Acl $Path $Acl

	# ----------- VERIFICA
	$FixACL = Get-Acl "C:\Windows\System32\spool\drivers"
	$VerifyACL = $FixACL.AccessToString[0..32] -join ''

	If ($VerifyACL -like "*NT AUTHORITY\SYSTEM Deny  Modify*") {
		Write-Host '[+] Patch attivata con successo'
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

    # ----------- VERIFICA
	$FixACL = (Get-Item $Path).GetAccessControl('Access')
	$VerifyACL = $FixACL.AccessToString[0..32] -join ''

	If ($VerifyACL -notlike "*NT AUTHORITY\SYSTEM Deny  Modify*") {
		Write-Host '[+] Patch DISattivata con successo'
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
		Write-Host '[>] ACL attivata'
	} Else {
		Write-Host '[<] ACL DISattivata'
	}
}
