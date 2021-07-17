# PrintNightmare

<br>

This repo is inteded to help sysadmins to find and mitigate the vulnerability known as "Print Nightmare"

<br>

## PrintNightmareCheck

This bash module has the purose to check hosts vulnerable state to CVE-2021-34527.
It has some dependencies. Just run it and the dependencies will be verified.

<br>

## No-Nightmare.ps1

This powershell module has the purpose to mitigate the CVE-2021-34527 vulnerability; it's not a patch but just a workaround.

One phase of the RCE exploit is the deployment of a DLL inside a spooler' subdirectory. This can be avoided by restricting
write access to the main spooler directory with ACL.

