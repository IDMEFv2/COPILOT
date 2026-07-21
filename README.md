# Ruleset → IDMEF Report

This report lists the ruleset files copied from IDMEFv2/Concerto-SIEM/logstash/rulesets into this repository (IDMEFv2/COPILOT/rulesets), with the rule ids and example sample lines found in each file. The "Comments" column notes anything interesting or any inference applied to the corresponding IDMEF file in idmef/.

Note: mappings in idmef/ were best-effort inferred from pattern named captures, samples and rule metadata. Some idmef files are fully populated, others are skeletons with notes requesting review.

Commit references:
- Batch 1: https://github.com/IDMEFv2/COPILOT/commit/2ab5ca75f14ad3dad9dbaada2ef2996f189c79b1
- Batch 2: https://github.com/IDMEFv2/COPILOT/commit/c693bcc682292a2fe7c30a6394c38e5cff123eab
- Final population pass: https://github.com/IDMEFv2/COPILOT/commit/4ee280f9ea1386e21445edb5ba1f0bde303a7079

---

## Table of rulesets (name — rule id(s) — sample(s) — comment)

| Ruleset file | Rule ID(s) | Sample(s) (from ruleset) | Comment / inference note |
|---|---:|---|---|
| nginx.yml | 5643 | `80.214.18.98 - - [18/Jul/2024:06:09:30 +0000] "GET /favicon.ico HTTP/1.1" 404 555 "http://141.95.158.49:8080/" "Mozilla/5.0 ..."` | HTTP status captured → translate dictionary added in idmef/nginx.yml (404→Invalid Web page access). Source IP mapped to [Source][0][IP]. |
| ssh.yml | 1902,1904,1905,1906,1908,1909,... | `Dec  9 16:00:35 itguxweb2 sshd[24541]: Failed password for root from 12.34.56.78 port 1806` | Authentication successes/failures mapped to Access category; several rules in idmef/ssh.yml populated with Source IP, Target User and Analyzer metadata. |
| sonicwall.yml | 4600,4601,4602,... | `Mar 10 13:44:49 ... id=firewall ... msg="Administrator login allowed" ... src=192.168.3...` | Parsed fw, pri, category, msg; idmef includes priority and Network.Firewall category inference. |
| cisco-asa.yml | 195,196,197,... | `%ASA-4-410001: Dropped UDP DNS packet_type ...` | Many ASA event codes; idmef/cisco-asa.yml contains Network.Dropped mapping for key patterns. |
| apc-emu.yml | 2800,2801,2802,... | `EMU: Probe 2 'Loc Env Probe 2' high  humidity violation, '40%RH'.` | Hardware/environment events → Category = Environment.Hardware in idmef/apc-emu.yml. |
| su.yml | 10002,10000 | `hids su: BAD SU afonyashin to root on /dev/ttyp0` | Access events; idmef/su.yml populated with Description templates. |
| sudo.yml | 2700,2701 | `sudo:   cpatel : TTY=pts/0 ; PWD=/etc/... ; USER=root ; COMMAND=./resin start` | Mapped to Access category; idmef/sudo.yml includes Target user and templated descriptions. |
| rsyslog.yml | 101000,101001 | `rsyslogd: [origin software="rsyslogd" ...] exiting on signal 15.` | System service start/stop mapped to System.Service; idmef/rsyslog.yml created. |
| arpwatch.yml | 4200,4201,4202,... | `arpwatch: new activity 12.34.56.78 0:20:a9:a:c:2a` | ARP events mapped to Network.Anomaly; idmef/arpwatch.yml created. |
| bonding.yml | 4800,4801,... | `kernel: bonding: bond0: backup interface eth0 is now up` | Network interface and bonding events; idmef/bonding.yml skeleton created (some fields inferred). |
| cacti-thold.yml | 4500,4501 | `CactiTholdLog[19647]: smf-core-02 - 5 Minute CPU went above threshold of 85 with 90.8067 at trigger 1 out of 1` | Threshold/monitoring events; idmef/cacti-thold.yml skeleton created. |
| checkpoint.yml | 100,104,112,... | sample not present / patterns for SmartDefense alerts | Product parsing patterns copied; idmef/checkpoint.yml is skeletal pending review. |
| f5-bigip.yml | 3600,3601,3602 | `bigconf.cgi: AUDIT -- Create MEMBER 10.5.253.52:0 ... User: admin` | Audit events -> idmef/f5-bigip.yml populated with configuration change mappings. |
| ftpd.yml | 2300,2301 | `ANONYMOUS FTP LOGIN FROM ... [IP]` | FTP login events mapped to Access (success/failure) in idmef/ftpd.yml. |
| honeyd.yml | 2600,2601,... | `honeyd[5711]: Killing attempted connection: tcp (127.0.0.1:46190 - 192.168.1.20:646)` | Honeypot connection attempts mapped to Recon/Scanning; idmef/honeyd.yml populated. |
| imapd.yml | 25605,25606,... | `imapd[1557]: Login failure user=amanda host=[192.168.1.233]` | IMAP auth failures populated in idmef/imapd.yml. |
| ipchains.yml | 700,701,... | `gateway kernel: Packet log: input DENY eth0 PROTO=6 1.2.3.4:3894 5.6.7.8:10008 ...` | Packet drop/accept rules mapped to Network.Dropped / Network.Accept in idmef/ipchains.yml. |
| ipfw.yml | 800,801,... | `kernel: ipfw: 65000 Deny UDP 200.65.7.49:1033 12.34.56.78:137 in via tun0` | IPFW deny/accept events mapped in idmef/ipfw.yml. |
| ironport.yml | 24501,24502,... | `Info: New SMTP ICID 30481570 ... reverse dns host unknown` | Mail gateway events → idmef/ironport.yml includes Email.Delivery and reputation mappings. |
| juniper-srx.yml | 22001,22002,... | `SRX2-NY RT_FLOW - RT_FLOW_SESSION_DENY ... source-address="1.2.3.4" ...` | Flow/RT events mapped to Network.Access in idmef/juniper-srx.yml. |
| keepalived.yml | 23201,23202,23203 | `Keepalived: Stopping Keepalived v1.1.7 ...` | HA/VRRP events mapped to Service.StateChange in idmef/keepalived.yml. |
| kojoney.yml | 20000,20001,... | `[SSHService ssh-userauth ...] root trying auth password` | Honeypot SSH events → idmef/kojoney.yml populated. |
| cisco-router.yml | 5600,5601,... | `%SEC-6-IPACCESSLOGP: list 101 denied tcp 1.2.3.4(1929) -> 5.6.7.8(80)` | Router ACL deny logs → idmef/cisco-router.yml skeleton (some fields inferred). |
| arbor.yml | 4300,4301,4302 | `pfDoS: anomaly Protocol id 92480 status ongoing severity 5 src 0.0.0.0/0 All dst 2.2.0.0/16 ...` | DoS/anomaly events. idmef/arbor.yml was left as skeleton for review (complex fields). |
| cisco-ips.yml | 5006,5001,... | SNMP trap patterns (no simple sample lines in some entries) | idmef/cisco-ips.yml left as a skeleton — SNMP trap OIDs require manual mapping. |
| clamav.yml | 3200,3201 | `/usr/share/doc/clamav-0.70/test/test2.badext: ClamAV-Test-Signature FOUND` | Malware detection mapping (idmef/clamav.yml populated with Malware.Detection and high priority). |
| mssql.yml | 1000 | `mssqlserver ... : Login failed for user 'probe'.` | DB auth failure patterns copied; idmef skeletons created (some populated earlier in other batches). |
| mysql.yml | 23601,... | `/usr/libexec/mysqld: Shutdown complete` | DB service and auth events copied; idmef skeletons created. |
| postgresql.yml | 23701,23702,... | `[2007-09-01 19:08:49] 192.168.2.99: FATAL:  password authentication failed for user "test_user"` | DB auth events mapped to Access.Failure in idmef. |
| pam.yml | 1,2,3 | `su(pam_unix)[17944]: session opened for user root by (uid=123)` | PAM session/auth events → idmef/pam.yml populated where possible. |
| paloalto.yml | 24601,24602,24603,... | `...,THREAT,...` and `...,SYSTEM,... Authentication failed for user admin via Web from ...` | Threat/SYSTEM events parsed; idmef/paloalto.yml populated with threat and auth mappings. |
| f5-bigip.yml | 3600,... | `bigconf.cgi: AUDIT -- Create MEMBER 10.5.253.52... User: admin` | Audit events mapped to Configuration.Change. |
| tripwire.yml | 24001,24002,24003 | `Tripwire: Added C:\\test\\AutoRetrieve...` | File integrity events → idmef/tripwire.yml skeleton / populated. |
| rsync.yml | 23401,23402,23403 | `rsyncd version 2.5.7 starting, listening on port 873` | Auth failed / rsync transactions; idmef/rsync.yml created. |
| other rulesets... | (many) | various samples | Several additional ruleset files were copied (full list is in `rulesets/`). Many idmef files were auto-populated; some were left as skeletons and marked for review. |

---

## Notes / Interesting findings

- Named-capture mapping:
  - Where patterns used named captures (e.g., `%{IP:ipAddr}` or `(?<descr>...)`) those capture names were mapped into IDMEF fields when the capture name indicated source/destination/user/process (examples: source → [Source][0][IP], destination → [Target][0][IP], user → [Target][0][User]).
  - For many patterns there were only positional or generic captures (GREEDYDATA). In these cases idmef files include templated [Description] fields and notes for manual review.

- Categories & Priorities:
  - Default priorities were conservative: Info / Medium unless the pattern strongly implied a malware or hardware failure (set to High).
  - Categories were inferred from ruleset names (e.g., `ssh`, `sudo`, `pam` → Access.*; firewall/ASA/sonicwall → Network.Firewall; virus/clamav → Malware.Detection). These are documented in each idmef/* file header as a note.

- Skeleton vs populated files:
  - Some idmef/*.yml were fully populated with per-rule fields (see examples: idmef/nginx.yml, idmef/ssh.yml, idmef/sudo.yml, idmef/clamav.yml, idmef/cisco-asa.yml, idmef/arpwatch.yml, idmef/ipchains.yml, idmef/ipfw.yml and others).
  - Other idmef files were left as skeletons with a `note:` asking for reviewer confirmation (e.g., idmef/arbor.yml, idmef/cisco-ips.yml, etc.) because patterns were complex or required interpretation of domain-specific fields (SNMP/oids, vendor codes, etc).

- Where to review:
  - Ruleset YAMLs: `rulesets/`  
  - Generated IDMEF YAMLs: `idmef/`  
  - Use the commit links above to see each change and review diffs.

---

## Suggested review checklist (short)
- Confirm global priority policy: should auth failures be upgraded to High across the board?
- Review one IDMEF file per major device family (firewalls, web servers, db servers, mail gateways) to validate category & field mapping.
- For SNMP-based rules (cisco-ips, snmptrap-based entries) consider manual mapping of OID → IDMEF fields.
- Validate descriptions and choose canonical wording if you want uniform wording across files.

---

If you want, I can provide:
- A raw CSV/TSV with one row per rule (ruleset, rule id, sample, inferred fields) to speed review.
- A shorter subset of high-priority rules only (auth failures, malware, firewall denies) for prioritized review.

Suggested commit message if you paste this into README.md and push:
"Add README report summarizing rulesets, rule IDs, samples and IDMEF inference notes"
