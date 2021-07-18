# PrintNightmare

<br>

This repo is inteded to help sysadmins to find and mitigate the vulnerability known as "PrintNightmare" (CVE-2021-34527).

<br>

## Module: PrintNightmareCheck

Written in bash, it uses RPC server mapping to check if hosts are potentially vulnerable to CVE-2021-34527.
It has some dependencies. Just run it and read the output, the dependencies will be preventively verified.

<br>

## Module: No-Nightmare.ps1

This powershell module has the purpose to mitigate the CVE-2021-34527 vulnerability on the Windows host; it's not a patch but just a workaround.

One of the phases of the RCE exploit is the deployment of a DLL inside a subdirectory of "C:\Windows\System32\spool\drivers".
This can be avoided by restricting write access to the main directory using ACL.

