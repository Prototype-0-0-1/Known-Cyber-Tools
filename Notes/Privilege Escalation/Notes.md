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

Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.
You will notice these files have an "s" bit set showing their special permission level.

List files that have SUID or SGID bits set:

    find / -type f -perm -04000 -ls 2>/dev/null

A good practice would be to compare executables on this list with [GTFOBins](https://gtfobins.github.io). Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set.
GTFObins does not directly provide us with an easy win. Typical to real-life privilege escalation scenarios, we will need to find intermediate steps that will help us leverage whatever minuscule finding we have.
Let's consider the example: The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner's privilege.
Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. At this stage, we have two basic options for privilege escalation: reading the /etc/shadow file or adding our user to /etc/passwd.

### Option 1: Read /etc/shadow & Crack the password

We see that the nano text editor has the SUID bit set by running the find / -type f -perm -04000 -ls 2>/dev/null command.

    "nano /etc/shadow" will print the contents of the /etc/shadow file.

We can now use the unshadow tool to create a file crackable by John the Ripper. To achieve this, unshadow needs both the /etc/shadow and /etc/passwd files.

### Option 2 : Add a new user that has root privileges

This would help us circumvent the tedious process of password cracking.
We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.

    openssl passwd -1 -salt <salt-vale> <password>

- -1 > MD5-based password algorithm

- -salt val > Use provided salt

Since we used the MD5 hash with salt, the output would be something like:

    $1$<salt-value>$<some-hash>

This entire thing is the salted hash. Which can then be added into the /etc/passwd file. Thus, at the end of the file, we add:

    hackeruser:$1$<salt-value>$<some-hash>:0:0:root:/root:/bin/bash

- hackeruser > it is the username
- The entire salted hash has to be pasted here
- root:/bin/bash was used to get a root shell

Once our user is added (please note how root:/bin/bash was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges.

## Capabilities

Another method system administrators can use to increase the privilege level of a process or binary is "Capabilities". Capabilities help manage privileges at a more granular level.

The capabilities man page provides detailed information on its usage and options. We can use the getcap tool to list enabled capabilities.

When run as an unprivileged user, getcap -r / will generate a huge amount of errors, so it is good practice to redirect the error messages to /dev/null.

    getcap -r / 2>/dev/null

GTFObins has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

## Cron Jobs

Cron jobs are used to run scripts or binaries at specific times. By default, they run with the privilege of their owners and not the current user. While properly configured cron jobs are not inherently vulnerable, they can provide a privilege escalation vector under some conditions.
The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

Each user on the system have their crontab file and can run specific tasks whether they are logged in or not. As you can expect, our goal will be to find a cron job set by root and have it run our script, ideally a shell.

Any user can read the file keeping system-wide cron jobs under /etc/crontab

    cat /etc/crontab

Find a script that is running which can be accessed by the current user.
We can easily modify it to create a reverse shell, hopefully with root privileges.

The script will use the tools available on the target system to launch a reverse shell.
Important points:

1. The command syntax will vary depending on the available tools. (e.g. nc will probably not support the -e option you may have seen used in other cases)
2. We should always prefer to start reverse shells, as we not want to compromise the system integrity during a real penetration testing engagement.

Crontab is always worth checking as it can sometimes lead to easy privilege escalation vectors. The following scenario is not uncommon in companies that do not have a certain cyber security maturity level:

1. System administrators need to run a script at regular intervals.
2. They create a cron job to do this
3. After a while, the script becomes useless, and they delete it
4. They do not clean the relevant cron job

This change management issue leads to a potential exploit leveraging cron jobs.

Consider a situation where the antivirus.sh script was deleted, but the cron job still exists.
If the full path of the script is not defined, cron will refer to the paths listed under the PATH variable in the /etc/crontab file. In this case, we should be able to create a script named "antivirus.sh" under our user's home folder and it should be run by the cron job.

In the odd event you find an existing script or task attached to a cron job, it is always worth spending time to understand the function of the script and how any tool is used within the context. For example, tar, 7z, rsync, etc., can be exploited using their wildcard feature.

## PATH

If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. PATH in Linux is an environmental variable that tells the operating system where to search for executables.
For any command that is not built into the shell or that is not defined with an absolute path, Linux will start searching in folders defined under PATH. (PATH is the environmental variable were are talking about here, path is the location of a file).

If we type “thm” to the command line, these are the locations Linux will look in for an executable called thm. The scenario below will give you a better idea of how this can be leveraged to increase our privilege level. As you will see, this depends entirely on the existing configuration of the target system.

1. What folders are located under $PATH
2. Does your current user have write privileges for any of these folders?
3. Can you modify $PATH?
4. Is there a script/application you can start that will be affected by this vulnerability?

If any writable folder is listed under PATH we could create a binary named thm under that directory and have our “path” script run it. As the SUID bit is set, this binary will run with root privilege

A simple search for writable folders can done using the command:

    find / -writable 2>/dev/null

The output of this command can be cleaned using a simple cut and sort sequence.

Comparing it's output wiht the PATH, will help us find folders we could use.

An alternative could be the command below.

    find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u

We have added “grep -v proc” to get rid of the many results related to running processes.

Usually, subfolders under /usr are not writable
The folder that will be easier to write to is probably /tmp. At this point because /tmp is not present in PATH so we will need to add it. As we can see below, the “export PATH=/tmp:$PATH” command accomplishes this.

At this point the path script will also look under the /tmp folder for an executable named with the same name as the privileged script.
Creating this command is fairly easy by copying /bin/bash in the script under the /tmp folder.

We have given executable rights to our copy of /bin/bash, please note that at this point it will run with our user’s right. What makes a privilege escalation possible within this context is that the path script runs with root privileges.

## NFS

Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help you gain root access on the target system. Some cases will also require using both vectors, e.g. finding a root SSH private key on the target system and connecting via SSH with root privileges instead of trying to increase your current user’s privilege level.

NFS (Network File Sharing) configuration is kept in the /etc/exports file. This file is created during the NFS server installation and can usually be read by users.

    cat /etc/exports

The critical element for this privilege escalation vector is the “no_root_squash” option. By default, NFS will change the root user to nfsnobody and strip any file from operating with root privileges. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

We will start by enumerating mountable shares from our attacking machine.
We will mount one of the “no_root_squash” shares to our attacking machine and start building our executable.
As we can set SUID bits, a simple executable that will run /bin/bash on the target system will do the job.
Once we compile the code we will set the SUID bit.
If we have worked on the mounted share so there was no need to transfer them.
Notice the nfs executable has the SUID bit set on the target system and runs with root privileges.
