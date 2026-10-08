# SPL Query Reference

All queries run against index=wineventlog with Sysmon and Windows Event Log data.

---

## Query 1 -- top: Most Common Processes (Sysmon EID 1)

**Purpose:** Find the top 10 processes by launch frequency over the last 24 hours. Establishes your normal baseline so anomalies stand out.

```spl
index=wineventlog earliest=-24h EventCode=1
| top limit=10 Image
```

**Result:** svchost.exe dominated, followed by Splunk Universal Forwarder processes, cmd.exe, and Windows Defender. This is what normal looks like on a managed Windows endpoint.

**Lesson:** top is a single command that counts, sorts descending, and calculates percentage automatically. Use it any time you want "what is most common" without writing stats + sort.

---

## Query 2 -- rare: Rarest DNS Queries (Sysmon EID 22)

**Purpose:** Surface the least-seen domains queried across your environment. Malware and C2 beaconing traffic appears here because it queries unusual domains infrequently while legitimate traffic is noisy and repetitive.

```spl
index=wineventlog earliest=-24h EventCode=22
| rare limit=10 QueryName
```

**Result:** All 10 rarest entries were internal Active Directory lookups -- DC locators, Kerberos SRV records, Global Catalog queries. This is a clean baseline. In a real incident, an unfamiliar external domain mixed in here is your lead.

**Lesson:** rare surfaces statistical outliers but outlier does not equal malicious. You still need context -- internal AD machinery vs unknown external domain -- to separate baseline from threat.

---

## Query 3 -- timechart: Logon Failures Over Time (EID 4625)

**Purpose:** Bin failed logon events into hourly buckets. A sudden spike in one hour against a flat baseline is the brute force signature.

```spl
index=wineventlog earliest=-24h EventCode=4625
| timechart span=1h count
```

**Result:** 6 events spread across 24 hours, all zeros on the timeline. Flat baseline. To generate a visible spike, enter the wrong password 5+ times on the lock screen and rerun.

**Lesson:** timechart turns raw events into a time series. Flat line is your baseline. Any bucket that breaks the pattern is the alert.

---

## Query 4 -- eval: Classify Logons by Business Hours vs Off-Hours (EID 4624)

**Purpose:** Create a new field on the fly that labels each logon as business or off-hours. Off-hours logons from privileged accounts are a common indicator of compromise or insider threat.

```spl
index=wineventlog earliest=-24h EventCode=4624
| eval hour_of_day=strftime(_time, "%H")
| eval shift=if(hour_of_day>=9 AND hour_of_day<17, "business_hours", "off_hours")
| stats count by shift
```

**Result:** 352 off-hours logons. This is expected in a lab running overnight -- Windows and AD generate continuous background authentication. In production, this number and the accounts behind it would drive the investigation.

**Lesson:** eval creates fields that do not exist in the raw event. strftime converts Unix timestamps into readable time parts. if() applies conditional logic inline. Combined, they turn a raw timestamp into an analyst-meaningful category.

---

## Query 5 -- rex: Extract Executable Name from Command Line (Sysmon EID 1)

**Purpose:** Sysmon logs the full command line path for every process. rex uses regex to extract just the filename, making the data groupable and readable.

```spl
index=wineventlog earliest=-24h EventCode=1
| rex field=Image "(?P<exe_name>[^\\\\]+)$"
| stats count by exe_name
| sort -count
| head 10
```

Note: Use the Image field (full path) rather than CommandLine to avoid backslash escaping issues in the Splunk UI. The regex anchors to the end of the string ($) and captures everything after the last backslash.

**Lesson:** rex named capture groups use (?P<fieldname>pattern) syntax. Backslashes in Splunk SPL require double escaping -- one backslash in the actual string needs four backslashes in the search bar (\\\\). Type regex directly in Splunk's search bar rather than pasting to avoid curly quote conversion.

---

## Query 6 -- transaction: Process Lifecycle Grouping (Sysmon EID 1)

**Purpose:** Group all events sharing the same ProcessGuid into a single row. Each row represents one complete process lifecycle with duration (how long it ran) and eventcount (how many events it generated). Long-running processes with high event counts are worth investigating.

```spl
index=wineventlog earliest=-24h EventCode=1
| transaction ProcessGuid maxspan=1h
| table ProcessGuid, duration, eventcount, Image, CommandLine
| sort -duration
```

**Result:** 621 unique process transactions. Most had duration=0 because Sysmon only captured one event per process -- they spawned and nothing else was logged for them. The ProcessGuid column shows the unique identifier Sysmon assigns to every process at creation.

**Lesson:** transaction correlates multiple events into one record per entity. This is how you build process trees and track attacker activity across multiple log entries. stats is faster for counting -- use transaction when you need duration, event sequences, or grouping across time.

---

## Query 7 -- stats dc(): Beaconing Detection via Distinct Domain Count (Sysmon EID 22)

**Purpose:** dc() is distinct count. This query compares total DNS queries against unique domains per host. A high query count with a low unique domain count means the same domain is being hit repeatedly -- the beaconing signature.

```spl
index=wineventlog earliest=-24h EventCode=22
| stats dc(QueryName) as unique_domains, count as total_queries by host
| sort -total_queries
```

**How to use the result:** Calculate the ratio of total_queries to unique_domains. A ratio of 1:1 is normal browsing (many queries, many different domains). A ratio of 50:1 (50 queries, 1 domain) is a beaconing indicator. Malware checks in with C2 on a timer -- it does not browse.

**Lesson:** dc() inside stats is one of the most powerful hunting functions in Splunk. Anywhere you want to count unique values of one field grouped by another, dc() is the tool.

---

## Query 8 -- where + match: Macro Malware Parent-Child Detection (Sysmon EID 1)

**Purpose:** Office applications should never spawn cmd.exe or powershell.exe directly. When they do, a malicious macro executed. This query is a production-ready detection rule.

```spl
index=wineventlog earliest=-24h EventCode=1
| eval parent=lower(ParentImage)
| eval child=lower(Image)
| where (match(parent,"winword\.exe") OR match(parent,"excel\.exe")) AND (match(child,"cmd\.exe") OR match(child,"powershell\.exe"))
| table _time, host, ParentImage, Image, CommandLine
| sort _time
```

**Result:** No results. Lab is clean. In a real macro malware infection (Emotet, QakBot, Agent Tesla delivery), this query would return rows showing exactly which Office file triggered the shell and what command ran.

**Lesson:** where + match() applies regex filtering mid-pipeline. eval lower() normalizes case first so WINWORD.EXE and winword.exe both match the same pattern. Parent-child process relationships are one of the highest-fidelity detection signals in endpoint security because legitimate software has predictable and consistent spawn behavior.

---

## Query 9 -- rename + fields + table: Analyst-Ready Output (EID 4624)

**Purpose:** Raw Splunk field names like Account_Name and Logon_Type are not report-ready. rename gives them readable labels. fields strips everything else. table formats the final output. This is what you do before putting data into an incident report.

```spl
index=wineventlog earliest=-24h EventCode=4624
| stats count by host, Account_Name, Logon_Type
| rename host as Hostname, Account_Name as Username, Logon_Type as LogonType, count as TotalLogons
| fields Hostname, Username, LogonType, TotalLogons
| sort -TotalLogons
| head 20
```

**Result:** Clean table showing Hostname, Username, LogonType, TotalLogons for all accounts that authenticated in the last 24 hours. Visible accounts: Administrator, DOMAIN-CONTROLLER$, SYSTEM, LOCAL SERVICE, NETWORK SERVICE, WIN11-CLIENT$. All expected for an AD environment.

**Logon Type reference for 4624:**
- Type 2: Interactive (local keyboard login)
- Type 3: Network (file share, mapped drive)
- Type 4: Batch (scheduled task)
- Type 5: Service (service account startup)
- Type 10: RemoteInteractive (RDP)
- Type 11: CachedInteractive (cached domain credentials, offline)

**Lesson:** rename + fields + table is the final pipeline stage before export. The difference between raw Splunk output and something a manager can read is usually two commands.

---

## Query 10 -- dedup: Unique Logon Sources Per Account (EID 4624)

**Purpose:** Keep only the first occurrence of each unique account and source IP combination over 7 days. This gives you a map of where each account normally authenticates from. A new IP that was not present in the baseline period is the anomaly.

```spl
index=wineventlog earliest=-7d EventCode=4624
| dedup Account_Name, IpAddress
| table Account_Name, IpAddress, _time
| sort Account_Name
```

**Note on empty results:** IpAddress is often null in domain authentication events because the DC records the computer account rather than the workstation IP. In environments with network logon events or VPN authentication, this field populates reliably.

**How to use this operationally:** Run it over a 30-day baseline period to build a normal source map. Then run it over the last 24 hours and compare. Any account appearing from an IP not in the baseline is worth investigating -- especially privileged accounts.

**Lesson:** dedup field1, field2 keeps only the first event per unique combination of those fields. Use it to build baselines and reduce noise when you care about unique entities, not event counts.
