# Splunk SPL Core User Reference

This repo is a personal reference and study guide built during Project 2.4 of my SOC analyst home lab. Every query here was written and run against real Windows and Sysmon logs I generated in my own environment. No synthetic data, no copy-paste from documentation -- these all returned actual results.

The goal was to get hands-on with the ten SPL commands that show up repeatedly in threat hunting, incident response, and on the Splunk Core Certified User exam. Each query includes the purpose, the SPL, and the one thing you should take away from it.

## Lab Environment

| Machine | IP | Role |
|---|---|---|
| Windows Server 2022 | 192.168.10.10 | Domain Controller, DNS, AD DS |
| Windows 11 | 192.168.10.20 | Endpoint client |
| Ubuntu Server 24.04 | 192.168.10.30 | Splunk Enterprise host |
| Kali Linux | 192.168.10.40 | Attacker box |

Domain: homelab.local
Index used: wineventlog
Data sources: Windows Event Log + Sysmon via Universal Forwarder

## What Sysmon Adds

Windows Event Log gives you logons, process creation (4688), and account changes. Sysmon goes deeper. It logs the full command line of every process (EID 1), every DNS query every process makes (EID 22), file creation (EID 11), registry changes (EID 13), and network connections (EID 3). The combination of both gives you the coverage a real SOC runs on.

## Queries Covered

| # | Command | Detection Use Case |
|---|---|---|
| 1 | top | Top processes by frequency -- baseline normal activity |
| 2 | rare | Rarest DNS queries -- surface beaconing and C2 |
| 3 | timechart | Logon failures over time -- detect brute force |
| 4 | eval + if | Classify events by business hours vs off-hours |
| 5 | rex | Extract executable names from raw command lines |
| 6 | transaction | Group events by process lifecycle |
| 7 | stats dc() | Distinct domain count per host -- beaconing ratio |
| 8 | where + match | Parent-child process detection for macro malware |
| 9 | rename + fields + table | Format output for analyst reports |
| 10 | dedup | Unique logon sources per account over time |

Full SPL for each query is in [queries/spl-reference.md](queries/spl-reference.md).

Detailed notes with explanations and lessons learned are in [queries/notes.md](queries/notes.md).

## How to Use This

If you are studying for the Splunk Core Certified User exam, the commands in this repo cover a large portion of what gets tested: stats functions, eval expressions, search filtering, time functions, and output formatting. The difference between reading about these and running them yourself is significant. The exam tests whether you understand what a command does, not just what it is called.

If you are doing blue team work, queries 2, 7, and 8 are the most directly applicable to real threat hunting. Query 2 (rare DNS) and query 7 (dc() beaconing ratio) work on any network with Sysmon deployed. Query 8 is a production-ready detection rule for macro malware.

## Related Repos

- [HowIBuiltMyHomeLab](https://github.com/CodePyschologist/HowIBuiltMyHomeLab) -- Network build, VM setup, AD DS
- [wireshark-protocol-analysis](https://github.com/CodePyschologist/wireshark-protocol-analysis) -- Protocol captures and analysis
- [windows-eventlog-reference](https://github.com/CodePyschologist/windows-eventlog-reference) -- Key event IDs explained
- [splunk-lab-build](https://github.com/CodePyschologist/splunk-lab-build) -- Splunk install and forwarder config
- [sysmon-detection-engineering](https://github.com/CodePyschologist/sysmon-detection-engineering) -- Sysmon deployment and event verification
- [bots-investigation](https://github.com/CodePyschologist/bots-investigation) -- BOTS v1 full attack chain investigation
