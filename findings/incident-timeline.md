# Incident Timeline — SSH Brute-Force Detection and Response

**Language:** English | [Versi Bahasa Indonesia](incident-timeline.id.md)

## Incident Summary

A controlled sequence of repeated SSH authentication attempts was generated from Kali Linux toward Ubuntu in a VMware host-only lab. The activity did not originate from the public internet.

## Environment

- Simulation source: Kali Linux — `192.168.82.130`
- Target endpoint: Ubuntu (`Falen-Vmware`) — `192.168.82.129`
- Monitoring platform: self-hosted Wazuh — `192.168.82.131`
- Agent: `ubuntu-falen` (ID `001`)
- Target username: `user`
- Monitored service: SSH
- Ubuntu/Wazuh timestamps: WIB (`+07:00`)

## Timeline

| Time (WIB, 11 October 2026) | Event | Evidence |
|---|---|---|
| `13:41:06–13:41:08` | Ubuntu `/var/log/auth.log` recorded 8 `Failed password` lines from `192.168.82.130` for username `user` over a few seconds. | `source-ip-investigation.log`, screenshot `05-ubuntu-auth-log-failed-passwords.png` |
| `13:41:07.779` | Wazuh Threat Hunting displayed rule `5763`, level `10`, for an SSH brute-force pattern. The event details identify agent `ubuntu-falen`, source IP `192.168.82.130`, username `user`, and MITRE ATT&CK `T1110`. The `full_log` of the alert is the fourth failed attempt (`13:41:06.530677`). | Screenshots `06-wazuh-bruteforce-alert.png` and `07-wazuh-alert-details.jpg` |
| `13:41:07` | The Active Response log showed `firewall-drop` starting. Ubuntu firewall inspection showed `DROP` rules for source `192.168.82.130`. | Screenshot `08-active-response-firewall-drop.png` |
| `13:43:04–13:43:07` | SSH logs recorded connections from the same source with `Timeout before authentication`. | `source-ip-investigation.log` |
| `13:44:08` | The Active Response log recorded the `delete` command for `firewall-drop`, 181 seconds after the block was added (configured timeout: 180 seconds). | `active-responses-excerpt.log` |
| At final endpoint verification | The endpoint showed no active block, while SSH and the Wazuh Agent remained active. Kali's `nc` screenshot separately reports TCP/22 as open. | `response-verification.txt`, `nc` output in screenshot `04-hydra-no-valid-password.png` |
| After the simulation | Verification recorded `PasswordAuthentication no`, `MaxAuthTries 3`, active SSH, an active Wazuh Agent, and no active block for the source IP. | `response-verification.txt` |

**Timestamp note:** This timeline uses the Ubuntu and Wazuh timestamps (WIB, UTC+7). The Kali VM runs on `America/New_York` (UTC-4), 11 hours behind WIB, so Hydra's displayed times (`02:40:52`-`02:42:34`) correspond to `13:40:52`-`13:42:34` WIB. The screenshot does not show when `nc` was run. The only later connection from the source in `auth.log` is at `13:44:26`, after the block was removed, which is consistent with the `nc` check but is not confirmed by the screenshot.

## Investigation Findings

- Source `192.168.82.130` is the Kali VM in this lab.
- The targeted service was SSH on Ubuntu `192.168.82.129`, username `user` was tested with incorrect passwords.
- Hydra displayed `0 valid password found`.
- 8 `Failed password` lines are visible in the log excerpt for activity associated with rule `5763`. The alert was generated on the fourth one: `ossec.conf` on the agent collects both `/var/log/auth.log` and `journald`, so each event was counted twice toward the rule frequency of 8 (details in the incident report, Section 3).
- No `Accepted password` or `Accepted publickey` event from the source was found in the reviewed excerpt for this attempt.
- Final verification found no active source-IP block and showed SSH and the Wazuh Agent as active.
- The reviewed artifacts do not show related privilege-escalation evidence, that conclusion is limited to the evidence and time window reviewed.

## Initial Attempt and Configuration Restoration

The initial attempt before the main simulation left one `Failed password` line in `attempt1-throttled-auth.log` and did not trigger rule `5763`. Lab notes indicate that OpenSSH controls (`MaxAuthTries` and `PerSourcePenalties`) limited failures during the initial attempt. The controls were temporarily relaxed for the controlled detection simulation and restored afterward.

Final verification records:

```text
SSH: active
WAZUH AGENT: active
PasswordAuthentication no
maxauthtries 3
ACTIVE RESPONSE BLOCK: No active block
```

## Response Flow

**SSH failures → Wazuh rule 5763 → Active Response `firewall-drop` → temporary source-IP block → endpoint recovery verification → restore hardened SSH configuration.**

