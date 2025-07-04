# 🧠 MITRE ATT&CK Mapping – Friday Overtime Investigation

This file documents the behavior observed during analysis of the `pRsm.dll` malware sample, mapped to relevant MITRE ATT&CK techniques. These mappings help defenders understand attacker objectives and align detections.

---

## 🔍 Observed Techniques

| Tactic         | Technique ID   | Technique Name                  | Description                                      |
|----------------|----------------|----------------------------------|--------------------------------------------------|
| Collection     | T1123          | Audio Capture                   | Captures microphone input using MgBot plugin     |
| Command & Control | T1071.001   | Application Layer Protocol: Web | MgBot likely communicates via web-based protocol |

---

## 🧭 Mapping Process

- **Technique T1123** was chosen based on pRsm.dll’s function as an audio capture plugin.
- **Technique T1071.001** was included based on known MgBot C2 communication patterns (TCP/UDP, HTTP).

> These mappings were confirmed using MITRE ATT&CK Navigator and OSINT from public threat reports.

---

![MITRE Mapping Screenshot](screenshots/mitre_mapping_t1123_t1071.png)  
*Mapped malware behaviors using ATT&CK Navigator to visualize adversary tactics and techniques.*<br><br>
