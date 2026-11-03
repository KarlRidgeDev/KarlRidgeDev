# Penetration Testing Report — Metasploitable Lab

**Prepared by:** Karl Ridge  
**Assessment date:** 17 October 2026 (reconstructed from lab notes)  
**Report date:** 3 November 2026  
**Assessment type:** Authorised educational penetration-testing exercise  
**Classification:** Public portfolio case study — no client or production systems assessed  
**Status:** Retrospective report; original console evidence is not fully preserved

---

## 1. Executive summary

I used Kali Linux, Nmap and the Metasploit Framework to assess an intentionally vulnerable Metasploitable virtual machine in a controlled VirtualBox lab. The goal was to practise the stages of a penetration test: defining scope, discovering network services, researching an identified service, testing it in an authorised environment and recommending ways to reduce risk.

The principal finding was **FTP service `vsftpd 2.3.4` exposed on TCP port 21**. That version is associated with **CVE-2011-2523**, a critical backdoor issue affecting a compromised distribution of vsftpd 2.3.4. A version banner alone does **not** prove that the installed binary contains the malicious backdoor.

The Metasploit module for this issue was investigated and a vulnerability check reportedly indicated the target *appeared vulnerable*. My original lab notes describe an exploitation demonstration, but the retained record does **not** include a reliable screenshot/transcript proving a persistent interactive shell or its privileges. This report therefore distinguishes the **observed service** and **reported tool output** from **unverified exploitation claims**.

**Overall assessment:** High-priority investigation and remediation required for a non-lab host; **potentially critical** if the backdoored build is confirmed. This deliberately vulnerable training VM was used only for learning.

## 2. Scope, authorisation and environment

| Item | Description |
| --- | --- |
| Target | Metasploitable virtual machine — `192.168.56.102` |
| Testing system | Kali Linux virtual machine |
| Virtualisation | VirtualBox isolated training lab / host-only network |
| Primary service in scope | FTP on `21/tcp` |
| Tools | Nmap, Metasploit Framework, SearchSploit |
| Authorisation | Self-controlled, intentionally vulnerable training system |
| Out of scope | Third-party websites, public IP addresses, real customer systems, denial-of-service tests |

The IP address above is an RFC 1918/private lab address, **not** a public target. The work on my personal Windows laptop was a **separate** exercise and is not assessed in this report.

## 3. Methodology and recorded activity

### 3.1 Reconnaissance and service discovery

A TCP port scan was run against the Metasploitable host and followed by service/version identification for FTP. The following commands are recorded in the prior lab notes:

```bash
nmap 192.168.56.102
nmap -sV -p 21 192.168.56.102
```

**Recorded result (summarised, not a raw terminal capture):**

```text
21/tcp  open  ftp  vsftpd 2.3.4
```

The initial scan reportedly returned multiple other open TCP ports. The complete scan output was not retained for this case study; additional ports are therefore **not** presented as confirmed individual findings.

### 3.2 Vulnerability research

I investigated the identified FTP service and its publicly documented security history using SearchSploit and the Metasploit Framework.

- **Potential issue:** CVE-2011-2523 — malicious backdoor in a compromised vsftpd 2.3.4 distribution
- **Affected service:** FTP, port 21/TCP
- **Published severity:** NVD CVSS v3.1 **9.8 (Critical)** for affected software
- **Potential impact:** Unauthorised command execution and loss of system confidentiality, integrity and availability **if the malicious backdoored build is actually present and exploitable**

**Important qualification:** The CVE applies to the compromised vsftpd 2.3.4 release archive, not automatically to every service advertising the version string.

### 3.3 Controlled validation

The Metasploit module investigated was:

```text
exploit/unix/ftp/vsftpd_234_backdoor
```

Earlier notes record that the module's **check** indicated that the target *appeared vulnerable*. An exploitation attempt was also made in the lab. Later session checks did **not** provide a reliable retained record of an active session.

**Validation status:** The assessment supports a **suspected backdoored service**, with a reported positive tool check, but **does not independently verify successful command execution or root privileges**. No invented console output or screenshots are included.

## 4. Findings

### PT-01 — Exposed vsftpd 2.3.4 service; potential backdoor

| Field | Assessment |
| --- | --- |
| Finding ID | PT-01 |
| Asset | `192.168.56.102` (intentionally vulnerable lab VM) |
| Port/protocol | `21/tcp` / FTP |
| Observed service | `vsftpd 2.3.4` |
| Related vulnerability | [CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523) |
| Risk | **Potentially Critical** if the compromised build is confirmed |
| Confidence | **Confirmed:** service/version banner; **reported:** Metasploit check; **unverified:** successful shell and privileges |

**Description.** Nmap service detection identified vsftpd 2.3.4. Public vulnerability records describe a maliciously modified distribution of this version that can provide unauthorised command execution. The service should be reviewed urgently on any real system, but version detection alone is insufficient to prove compromise.

**Evidence.** Prior lab notes record `21/tcp open ftp vsftpd 2.3.4` and the Metasploit vulnerability check reporting that the host appeared vulnerable. The original scan transcript, target binary hash and verified post-exploitation session output were not retained.

**Potential impact.** If the compromised backdoor build were present and reachable, an unauthenticated attacker could potentially obtain unauthorised access and run commands.

**Recommendations (for a real-world system).**
1. **Remove and replace** any suspected compromised vsftpd binary using a trusted, maintained software source. Verify package origin and integrity.
2. Disable FTP if unnecessary; otherwise restrict exposure through network access controls and use a secure file-transfer service where appropriate.
3. Review service logs, host integrity and indicators of unauthorised access where compromise is suspected.
4. Re-scan after remediation and confirm both the service version and whether the backdoor behaviour is absent.

**Retest criteria.** A follow-up assessment should demonstrate that the suspect build has been removed, the service exposure is appropriately restricted, and the previously observed indicator is no longer present. Retesting must use the same authorisation and lab boundaries.

## 5. Evidence register and limitations

| Evidence ID | Description | Status |
| --- | --- | --- |
| E-01 | FTP service discovery: `21/tcp open ftp vsftpd 2.3.4` | Recorded in previous lab notes; original Nmap output not attached |
| E-02 | Metasploit module `vsftpd_234_backdoor` investigation | Recorded in previous lab notes |
| E-03 | Metasploit `check` suggesting vulnerability | Reported result; no original console capture attached |
| E-04 | Verified interactive shell / privilege confirmation | **Not established by retained evidence** |
| E-05 | Remediation and subsequent retest | **Not performed**; VM remains intentionally vulnerable for training |

This document is a **retrospective learning report**, not an independent third-party penetration-test attestation. No screenshots have been created or simulated. Risk scoring comes from the published CVE description, not a verified measurement of this particular VM.

## 6. Conclusion and learning outcomes

This exercise provided hands-on experience with:

- Building an isolated lab environment and identifying in-scope hosts.
- Using Nmap for network reconnaissance and service-version enumeration.
- Mapping an observed software version to a publicly documented vulnerability.
- Using Metasploit to assess a suspected weakness under authorisation.
- Reporting confidence levels, evidence gaps, business impact and remediation.
- Recognising that identifying a service version is **not the same as proving exploitation**.

**Next improvement:** Preserve the full scan output, a timestamped result of the validation attempt and a safe, minimal proof of any demonstrated access. Add a retest record after a controlled remediation exercise.

## 7. References

- [NIST National Vulnerability Database — CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)
- [Rapid7 Metasploit module — vsftpd 2.3.4 backdoor](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb)
- [Original Kali Linux lab notes](README.md)

---

*Ethical statement: All testing described here was carried out in a self-controlled or otherwise authorised training environment. No production or third-party systems were targeted.*
