# Project 2.4 Study Notes -- SPL Core Commands

These are the things I actually learned running these queries, not just what the commands do on paper.

---

## How Splunk Pipelines Actually Work

Every SPL search is a pipeline. Data flows left to right through the pipe character (|). Each command receives the output of the one before it and transforms it.

The most important rule: filter early, transform late. Your index, sourcetype, and field filters go in the first line before any pipes. This limits the data Splunk has to process before it starts doing the expensive work like stats and transaction. A search that filters at the index level is dramatically faster than one that pulls everything and filters mid-pipeline.

```
index=wineventlog EventCode=1    <- filter here (fast, happens at index)
| stats count by Image           <- then transform (happens in memory)
| sort -count                    <- then sort
| head 10                        <- then limit output
```

If you put the EventCode filter after a pipe (| search EventCode=1), Splunk pulls all events from the index first and then filters. On large datasets this is the difference between a 2-second search and a 2-minute one.

---

## The Commands and What They Actually Do

**top and rare** are inverses of each other. top gives you the most common values of a field. rare gives you the least common. Both automatically count, calculate percentages, and sort. Neither requires a stats or sort command after it. For quick frequency analysis, these are faster to write than stats + sort.

The threat hunting use case for rare is real. In any environment with consistent normal behavior, the things that happen rarely are worth looking at. DNS is the best field to run rare against because legitimate applications query the same domains constantly (Windows Update, telemetry, AD) while malware tends to query domains it only needs once or on a slow timer.

**timechart** is for anything where time is the question. Brute force shows as a spike. Data exfiltration shows as sustained high volume. Beaconing sometimes shows as regular intervals. The span parameter controls the bucket size -- span=1h means one data point per hour, span=5m means one per five minutes. Smaller spans give more resolution but noisier charts.

**eval** is probably the most versatile command in SPL. It creates new fields by applying functions to existing ones. The functions worth knowing cold:

- strftime(_time, "%H") -- extract hour from timestamp (0-23)
- strftime(_time, "%A") -- day of week
- if(condition, value_if_true, value_if_false) -- conditional logic
- lower(field) -- convert to lowercase for case-insensitive matching
- len(field) -- length of a string (useful for detecting unusually long command lines)
- round(number, decimals) -- round a number
- mvcount(field) -- count values in a multivalue field

The eval + if() pattern for business hours classification is directly applicable to any time-based detection. You can extend it to flag weekend activity, holiday windows, or any custom time boundary relevant to your environment.

**rex** extracts new fields from raw text using regex. The syntax is:

```
| rex field=fieldname "(?P<new_field_name>pattern)"
```

The (?P<name>pattern) part is a named capture group. Whatever the pattern matches gets stored in new_field_name as a new field you can use in the rest of the pipeline.

The backslash escaping issue in Splunk's UI is a real friction point. In regex, a backslash is an escape character. In SPL strings, a backslash also needs escaping. So to match a literal backslash in the actual data, you need four backslashes in the search bar (\\\\). This trips people up constantly. The workaround is to extract from the Image field (which ends with the filename) rather than CommandLine (which has paths full of backslashes).

**transaction** groups events by a shared field value into one record. It adds two fields automatically: duration (time between first and last event in the group) and eventcount (number of events in the group). Use cases:

- Group all Sysmon events for one ProcessGuid to see a process's full lifecycle
- Group all events from one source IP within a time window to reconstruct an attack sequence
- Group all logon/logoff pairs for one session

The limitation of transaction is performance. It is memory-intensive because Splunk has to hold open groups waiting for new events that might join them. For large datasets, stats is faster if you only need counts. Use transaction when you actually need the duration or the event sequence.

**stats dc()** is distinct count. It answers "how many unique values of field X exist for each value of field Y." The beaconing detection pattern (dc(QueryName) per host) works because it quantifies the diversity of DNS traffic. A high total query count with a low distinct domain count is mathematically suspicious -- it means repetition, and repetition means automation.

Other useful stats functions beyond dc():

- count -- total events
- sum(field) -- sum of numeric values
- avg(field) -- average
- max(field), min(field) -- extremes
- list(field) -- all values as a list (multivalue)
- values(field) -- unique values as a list

**where** filters events mid-pipeline based on a condition. The difference between where and search:

- search is a keyword filter -- it matches against the raw event text or simple field values
- where evaluates an expression -- it can use functions, comparisons, AND/OR/NOT logic, and the match() function for regex

For detection logic involving multiple fields and conditions, where is the right tool. The macro malware detection (parent Office app spawning cmd or powershell) cannot be expressed cleanly with a simple search filter -- it needs where + match() to apply regex against two fields simultaneously.

**rename** changes field names. **fields** keeps only the fields you name (or drops them with a minus sign: | fields - fieldname). **table** displays the result as a formatted table with columns in the order you specify.

The output pipeline pattern is: rename to clean up names, fields to drop everything you do not need, table to format for display. This is what makes the difference between a search result and something you can put in a ticket.

**dedup** removes duplicate events based on field combinations. It keeps the first occurrence and drops subsequent ones. Use cases:

- Unique user-to-source-IP mappings (baseline building)
- Remove duplicate alerts so you count incidents, not events
- Get one row per unique combination of any fields you care about

The limitation: dedup keeps the first event chronologically, which may not always be what you want. If you need the most recent or the one with a specific field value, use stats with max(_time) or first()/last() instead.

---

## Things That Will Trip You Up on the Exam

**earliest and latest syntax.** The modifiers use shorthand: -24h is last 24 hours, -7d is last 7 days, -1mon is last month. earliest=0 means all time (used with BOTS and imported datasets that have no recent data). Always include earliest when you are not sure the default time picker is set correctly.

**stats vs transaction.** The exam will test whether you know when to use each. stats is for aggregation (counts, averages, sums). transaction is for grouping sequential events into sessions. If the question is about counting, use stats. If the question is about sessions, duration, or event sequences, use transaction.

**The pipe order matters.** You cannot reference a field created by eval in the same eval command. Create it first, then reference it in the next pipe. You also cannot use a where filter on a field that does not exist yet -- eval it first.

**table does not filter.** It only controls display order and which fields are shown. If you want to remove events, use where or search. If you want to remove fields, use fields. table is purely cosmetic.

**dedup vs stats for unique counts.** dedup keeps rows, stats aggregates them. If you want to count unique values, use stats dc(). If you want to see the actual unique rows, use dedup.

---

## Field Names That Vary by Sourcetype

This burned time during the BOTS investigation and will burn time again. Field names are not consistent across sourcetypes.

| Sourcetype | Source IP field | Destination field | URI field |
|---|---|---|---|
| stream:http | src_ip | dest_ip | uri_path |
| iis | c_ip | s_ip | cs_uri_stem |
| WinEventLog | IpAddress | -- | -- |
| Microsoft:Sysmon:Operational | SourceIp | DestinationIp | -- |
| suricata | src_ip | dest_ip | -- |

When a search returns no results and you expect results, check the field name for your sourcetype first. Use | fieldsummary or click on an event to see what fields actually exist.

---

## The Exam Domains This Covers

Splunk Core Certified User tests five areas. These queries cover most of them:

1. Splunk basics and search fundamentals -- covered by the filter-first principle and time modifier syntax
2. Using fields -- covered by eval, rex, rename, fields, table
3. Visualizations -- timechart output is the basis for most Splunk dashboards
4. Working with time -- strftime in eval, span in timechart, earliest/latest modifiers
5. Statistical commands -- stats with dc(), count, sum; top; rare; transaction; dedup

The commands you will definitely see on the exam: stats, eval, top, rare, timechart, table, rename, fields, dedup. The ones that are likely but less certain: rex, transaction, where with match().
