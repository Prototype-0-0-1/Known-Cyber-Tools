# Privelege Escalation Notes

[Reference](https://tryhackme.com/room/linprivesc)

Enumeration is the first step you have to take once you gain access to any system. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.

Enumeration checks (atleast):

    - hostname
    - uname -a
    - /proc/version
    - /etc/issue
    - ps [-A][axjf][aux]
    - env
    - sudo -l
    - ls
    - id
    - /etc/passwd
    - history
    - ifconfig
    - netstat [-a][-t][-u][-l][-s][-p][-i][-ano]
    - find [-name][-type][-perm][-user][-size][-time] :Find tools -> find / -name perl*|| find / -name python*|| find / -name gcc*
    - locate
    - grep

## Automated enumeration tools

These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.
These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

    - [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
    - [LinEnum](https://github.com/rebootuser/LinEnum)
    - [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester)
    - [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
    - [Linux Priv Checker](https://github.com/linted/linuxprivchecker)

## Kernel Exploit

[Reference: Linux Privilege Escalation - Kernel Exploits](https://steflan-security.com/linux-privilege-escalation-kernel-exploits/)

The following command can be used to manually enumerate kernel info:

    uname -a ; lsb_release -a; cat /proc/version /etc/issue /etc/*-release; hostnamectl | grep Kernel

The Kernel exploit methodology is simple:

    1. Identify the kernel version
    2. Search and find an exploit code for the kernel version of the target system
    3. Run the exploit

Although it looks simple, please remember that a failed kernel exploit can lead to a system crash. Make sure this potential outcome is acceptable within the scope of your penetration testing engagement before attempting a kernel exploit.

Search for the exploit can be done using Google for an existing exploit code, a [CVE database](https://www.linuxkernelcves.com/cves), exploit-db, searchsploit. Note: be extremely specific of the kernel version. Read the comments of the code carefully, some exploits might need further interaction. You can transfer the exploit code from your machine to the target system using the SimpleHTTPServer Python module and wget respectively.

Another alternative would be to use a script like LES (Linux Exploit Suggester) but remember that these tools can generate false positives (report a kernel vulnerability that does not affect the target system) or false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

## Sudo
