# 🧪 Friday Overtime – Malware Analysis & CTI Lab

This project simulates a real-world malware investigation scenario based on a TryHackMe lab. I acted as a Cyber Threat Intelligence (CTI) analyst responding to an urgent malware incident at a financial institution. The goal was to analyze the samples, enrich IOCs, attribute the threat, and map behaviors using MITRE ATT&CK.

---

## 📝 Lab Summary

- **Scenario:** Simulated CTI response for SwiftSpend Finance  
- **Malware Type:** MgBot (modular RAT)  
- **APT Group:** Evasive Panda (aka BRONZE HIGHLAND)  
- **Target Platforms:** Windows (with Android linked activity)  
- **Skills Practiced:** Malware triage, threat attribution, MITRE mapping, IOC enrichment  

---

## 📂 Files Analyzed

- `pRsm.dll` *(main focus)*  
- `cbmrpa.dll`  
- `maillfpassword.dll`  
- `qmsdp.dll`  
- `wcdbcrk.dll`  

---

## 🔍 Key Artifact: `pRsm.dll`

- **SHA1 Hash:** `9d1ecbbe8637fed0d89fca1af35ea821277ad2e8`  
- **Confirmed As:** MgBot audio capture plugin  
- **Behavior:** Records microphone input  
- **Mapped MITRE Technique:** `T1123 - Audio Capture`  

---

## 🔗 IOC Enrichment

### ✅ Malicious Download URL

- **Original:**  
  `http://update.browser.qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296.exe`  
- **Defanged (via CyberChef):**  
  `hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296.exe`

### ✅ Command & Control IP

- **IP Address:** `122.10.90[.]12`  
- **First Seen:** 2020-09-14  
- **Defanged:** `122[.]10[.]90[.]12`

### ✅ Android Spyware Sample (Same C2 Infrastructure)

- **SHA1:** `951F41930489A8BFE963FCED5D8DFD79`  
- **Malware Family:** SpyAgent  
- **Platform:** Android  
- **First Seen:** June 2025  

---

## 🧠 MITRE ATT&CK Mapping

| Tactic       | Technique ID | Technique Name              | Description                          |
|--------------|--------------|-----------------------------|--------------------------------------|
| Collection   | T1123        | Audio Capture               | Microphone spying via plugin         |
| C2 (likely)  | T1071.001    | App Layer Protocol: Web     | Used for MgBot backdoor communication|

---

## 🛠️ Tools Used

- `unzip`, `sha1sum` (Ubuntu shell)  
- [VirusTotal](https://www.virustotal.com)  
- [CyberChef](https://gchq.github.io/CyberChef/)  
- WeLiveSecurity threat report  
- [MITRE ATT&CK Navigator](https://attack.mitre.org/matrices/enterprise/)

---

## 🧩 Screenshots

> _Place your screenshots in a `/screenshots` folder in the repo._

- `screenshots/unzip_sample.png`  
- `screenshots/sha1sum_result.png`  
- `screenshots/virustotal_lookup.png`  
- `screenshots/cyberchef_defang_url.png`

---

## 🧘 Lessons Learned

- Malware sample handling and hashing  
- Open-source intelligence (OSINT) lookup techniques  
- Threat attribution using public APT reports  
- MITRE ATT&CK behavioral mapping  
- Infrastructure reuse across platforms (Windows & Android)  
- Safe reporting practices using CyberChef (defanging)

---

## 📎 Blog Post

👉 Full write-up: **[Friday Overtime – Malware Analysis Lab Blog Post](#)**  
