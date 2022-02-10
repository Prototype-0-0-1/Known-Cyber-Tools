# Tools Known

This list is the list of tools & concepts I have used and learnt

## General / Applicable in all cases

1. Metasploit

## Reconnaissance

### OSINT

1. Hunder.io
2. Checkusernames
3. What's my name
4. Namecheckup
5. theHarvester
6. recon-ng
7. maltego

### Website/IP Info Gathering

1. whois
2. dig, nslookup, host
3. traceroute/tracert
4. Any search engine
5. [Threat Intelligence Platform](https://threatintelligenceplatform.com/)
6. Shodan
7. [VidewDNS.info](https://viewdns.info/)
8. [Censys Search](https://search.censys.io/)

### Subdomain Tools

1. DNS Dumpster
2. NM Mapper.com
3. Spyse
4. Sublist3r

## Scanning

1. Nmap
2. Nikto
3. Nessus

## Gaining Access

1. searchsploit

### Automated Credential Spray / Wordlist Attack / Cracking Passwords

1. brutespray
2. Hydra
3. John The Ripper
4. Hashcat
5. [wordlistctl](https://github.com/BlackArch/wordlistctl): Script to fetch, install, update and search wordlist archives from websites offering wordlists with more than 6400 wordlists available
6. [Haiti](https://noraj.github.io/haiti/#/): A CLI tool (and library) to identify hash types (hash type identifier)
7. [Mentalist](https://github.com/sc0tfree/mentalist): Mentalist is a graphical tool for custom wordlist generation
8. [CeWL](https://github.com/digininja/CeWL): CeWL is a Custom Word List Generator
9. [TTPassGen](https://github.com/tp7309/TTPassGen): Flexible and scriptable password dictionary generator which can support brute-force,combination,complex rule mode etc
10. [lyricpass](https://github.com/initstring/lyricpass): Generate lyric-based passphrase wordlists for offline password cracking.
11. [pnwgen](https://github.com/toxydose/pnwgen): Phone number Wordlist Generator

## Maintaining Access

- Tactics: Backdoor, Rootkits, User creation, Task scheduling, Persistence Scripts

## Covering Tracks

- Remove executables, remove scripts, remove temporary file, restore settings, uninstall rootkits, remove additional user accounts

## Privilege Escalation

[Linux PrivEsc](https://tryhackme.com/room/linprivesc) : Learn the fundamentals of Linux privilege escalation. From enumeration to exploitation, get hands-on with over 8 different privilege escalation techniques.

- [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester)
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- [Linux Priv Checker](https://github.com/linted/linuxprivchecker)

## Deserialization

- [ysoserial](https://github.com/frohoff/ysoserial) : A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization
- [ysoserial.net](https://github.com/pwntester/ysoserial.net) : A proof-of-concept tool for generating payloads that exploit unsafe .NET object deserialization.
- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [Java Unmarshaller Security](https://github.com/mbechler/marshalsec) : Java Unmarshaller Security - Turning your data into code execution

----------------

## Web Application Testing

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [XML External Entity (XXE) Injection Payload List](https://github.com/payloadbox/xxe-injection-payload-list)
- [Attack payloads](https://github.com/orgs/payloadbox/repositories)
- [Server Side Template Injection Payloads](https://github.com/payloadbox/ssti-payloads)
- [remote and local file inclusion](https://github.com/payloadbox/rfi-lfi-payload-list)
- [Command Injection Payload List](https://github.com/payloadbox/command-injection-payload-list#command-injection-payload-list)
- [Open Redirect Payload List](https://github.com/payloadbox/open-redirect-payload-list)
- [log4j-scan](https://github.com/fullhunt/log4j-scan) : A fully automated, accurate, and extensive scanner for finding vulnerable log4j hosts

1. Burp Suite
2. OWASP Zap

### Fuzzing

1. [dirbuster](https://gitlab.com/kalilinux/packages/dirbuster)
2. [gobuster](https://tools.kali.org/web-applications/gobuster)
3. [ffuf](https://github.com/ffuf/ffuf)
4. [WPScan: WordPress security scanner](https://github.com/wpscanteam/wpscan)
5. [Wfuzz](https://tools.kali.org/web-applications/wfuzz)
6. [dirb](https://tools.kali.org/web-applications/dirb)

### XSS

- [Cross Site Scripting ( XSS ) Vulnerability Payload List](https://github.com/payloadbox/xss-payload-list)

1. [XSStrike](https://github.com/UltimateHackers/XSStrike)
2. [BruteXSS Terminal](https://github.com/shawarkhanethicalhacker/BruteXSS)
3. [BruteXSS GUI](https://github.com/rajeshmajumdar/BruteXSS)
4. [XSS Scanner Online](http://xss-scanner.com/)
5. [XSSer](https://tools.kali.org/web-applications/xsser)
6. [xsscrapy](https://github.com/DanMcInerney/xsscrapy)

### SQL Injection

- [SQL Injection Payload List](https://github.com/payloadbox/sql-injection-payload-list)

1. [SQLMap](https://github.com/sqlmapproject/sqlmap) : Automatic SQL Injection And Database Takeover Tool
2. [jSQL Injection](https://github.com/ron190/jsql-injection) : Java Tool For Automatic SQL Database Injection
3. [BBQSQL](https://github.com/Neohapsis/bbqsql) : A Blind SQL-Injection Exploitation Tool
4. [NoSQLMap](https://github.com/codingo/NoSQLMap) : Automated NoSQL Database Pwnage
5. [Whitewidow](https://www.kitploit.com/2017/05/whitewidow-sql-vulnerability-scanner.html) : SQL Vulnerability Scanner
6. [DSSS](https://github.com/stamparm/DSSS) : Damn Small SQLi Scanner
7. [explo](https://github.com/dtag-dev-sec/explo) : Human And Machine Readable Web Vulnerability Testing Format
8. [Blind-Sql-Bitshifting](https://github.com/awnumar/blind-sql-bitshifting) : Blind SQL-Injection via Bitshifting
9. [Leviathan](https://github.com/leviathan-framework/leviathan) : Wide Range Mass Audit Toolkit
10. [Blisqy](https://github.com/JohnTroony/Blisqy) : Exploit Time-based blind-SQL-injection in HTTP-Headers (MySQL/MariaDB)

## Malware Analysis / Reverse Engineering

### Malware Analsysis

1. YARA
2. yaGen
3. Loki
4. Thor
5. [Intezer Analyze](https://analyze.intezer.com)
6. [Virtustotal](https://www.virustotal.com)
7. [Any.run](https://any.run/)
8. MobSF
9. [Pithus](https://beta.pithus.org/)
10. PE Studio

### Reverse Engineering

1. IDA Pro/Freeware
2. Ghidra : [Cheatsheet](https://ghidra-sre.org/CheatSheet.html)
3. x64dbg
4. dnSpy
5. gdb
6. radare2 / iaito
7. snowman c++
8. dex2jar
9. Java ByteCode Editor
10. Java Decompiler
11. Enigma
12. Krakatau
13. Java Disassembler
14. recaf
15. MARA Framework

### More

1. oledump

## Network Hacking

1. python3 -> scapy
2. wifite
3. fern
4. airmon-ng
5. aircrack-ng

## Malware Resources

[Ref](https://tryhackme.com/room/pyramidofpainax)
    [MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) are good resources to provide you with access to the samples, malicious feeds, and YARA results - these all can be very helpful when it comes to threat hunting and incident response.

    For detection rules, [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) is a great platform, where security professionals share their detection rules for different kinds of threats including the latest CVE's that are being exploited in the wild by adversaries.

    Fuzzy hashing is also a strong weapon against the attacker's tools. Fuzzy hashing helps you to perform similarity analysis - match two files with minor differences based on the fuzzy hash values. One of the examples of fuzzy hashing is the usage of [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html); on the SSDeep official website, you can also find the complete explanation for fuzzy hashing. 

## Additional Resources

- [have i been pwned](https://haveibeenpwned.com/)

- [Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/overview.html): An inventory of tools and resources about CyberSecurity
- [MSFconsole cheat sheet](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)
- [The Exploit Database Git Repository](https://github.com/offensive-security/exploitdb)
- [GTFOBins](https://gtfobins.github.io/)
- [Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/)

- [CVE Mitre](https://cve.mitre.org/)
- [NATIONAL VULNERABILITY DATABASE](https://nvd.nist.gov/)

- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
