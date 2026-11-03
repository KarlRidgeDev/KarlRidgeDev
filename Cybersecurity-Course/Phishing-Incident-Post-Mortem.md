# Phishing Incident — Post-Mortem Report

**Prepared by:** Karl Ridge  
**Report type:** Incident post-mortem / lessons learned  
**Training context:** Think Employment — Skills Bootcamp in Cyber Security (Level 3)  
**Incident type:** Phishing and suspected credential compromise  
**Scenario:** Simulated employee phishing incident  
**Status:** Educational case study, not a report of a real organisational breach

> **Scope and evidence note:** This is a portfolio adaptation of a training scenario previously discussed while studying incident response. The example timeline, actions and outcome are **illustrative**, not independently verified events, incident logs or the original submitted coursework. No real employee, organisation or victim is identified.

## 1. Executive summary

In this simulated incident, an employee receives an email that impersonates a trusted organisation and directs them to a fraudulent login page. The employee follows the link and enters their credentials. Suspicious account login activity is then detected.

The response focuses on confirming the alert, protecting the affected account, examining the extent of any misuse, restoring safe access, and improving defences. The main lesson is that an effective response should address both **technical controls** and **human factors** without blaming the person who was targeted.

**Potential impact:** Account takeover, unauthorised access to company services, exposure of sensitive data, and possible further phishing from the compromised account. The scenario does **not** provide evidence that data was stolen or that other accounts were compromised.

## 2. Incident overview

| Field | Details |
| --- | --- |
| Attack vector | Phishing email linking to a fake login page |
| Initial target | Employee account |
| Suspected issue | Credentials entered into an attacker-controlled page |
| Detection signal | Unusual login activity |
| Scope | Single example account initially; wider impact remains unconfirmed |
| Response framework | SANS incident response lifecycle |
| Evidence confidence | Hypothetical scenario; no real system logs available |

## 3. Illustrative timeline

These times demonstrate the sequence an incident analyst might document; they are **not real event timestamps**.

| Example time | Simulated event |
| --- | --- |
| 08:30 | Attacker prepares a spoofed email and fake sign-in page |
| 09:00 | Employee receives the email and follows the link |
| 09:05 | Employee enters credentials into the fraudulent page |
| 09:30 | Monitoring identifies unusual account login activity |
| 09:45 | Response team disables or secures the account, revokes sessions and blocks the malicious destination |
| 13:00 | Account credentials are reset, MFA is reviewed and access is restored after checks |
| Following day | Team reviews controls, reporting procedures and training opportunities |

The exact order and timing of containment, recovery and communications would depend on the confirmed facts and the organisation's incident response procedures.

## 4. Incident response — SANS lifecycle

### 4.1 Preparation
Before an incident, organisations should maintain an incident response plan, staff reporting channels, phishing-awareness training, email filtering, MFA and access to relevant logs. Roles and escalation routes need to be clear.

### 4.2 Identification
Review the reported email, sender details, link destination and authentication alerts. Check login timestamps, location anomalies, device information and account activity. Confirm whether the employee actually entered credentials; do not assume this from a click alone.

### 4.3 Containment
Protect the suspected account by revoking active sessions, changing credentials and disabling access temporarily where appropriate. Block the confirmed malicious URL or domain and search for additional recipients or similar messages. Preserve relevant logs before they expire.

### 4.4 Eradication
Remove the malicious email where feasible, address any account persistence such as unauthorised inbox rules or OAuth grants, and reset exposed credentials. Investigate whether other devices or accounts require attention.

### 4.5 Recovery
Re-enable account access only after reviewing account integrity, MFA and authentication activity. Monitor for repeat login attempts, additional suspicious rules or new outbound phishing.

### 4.6 Lessons learned
Conduct a blame-free review: what was detected, how quickly the alert was escalated, which controls helped or failed, and what evidence would have improved the response. Assign owners and deadlines to any agreed improvements.

## 5. Root cause and contributing factors

**Scenario trigger:** A convincing phishing message led the employee to a fraudulent login page.

**Potential contributing factors to investigate:**
- The email was delivered despite existing filtering.
- The destination resembled a legitimate sign-in experience.
- Account access controls may not have sufficiently limited the usefulness of stolen credentials.
- Suspicious behaviour was only recognised after the attempted credential compromise.

These are **hypotheses**, not confirmed failures of a particular company's controls. A real post-mortem should distinguish the immediate event, underlying system weaknesses and any gaps in detection or response.

## 6. Impact assessment and evidence gaps

**Known within the scenario:** The employee received a phishing email, entered credentials and unusual account activity was observed.

**Unknown or requiring verification:** Whether a successful unauthorised login occurred, whether MFA was bypassed, which resources were accessed, whether data was viewed or exported, and whether other identities were targeted.

Without authentication logs, email headers, audit trails or incident tickets, this case study **cannot assign a precise incident duration, financial cost or confirmed data-loss total**.

## 7. Recommendations and follow-up actions

| Priority | Recommended action | Intended improvement |
| --- | --- | --- |
| High | Enforce phishing-resistant MFA where feasible | Reduce successful credential-based account takeover |
| High | Establish rapid reporting and session-revocation procedures | Reduce time to contain suspected compromise |
| High | Monitor suspicious sign-ins and account rule changes | Improve early detection and investigation |
| Medium | Strengthen email filtering and malicious-link protections | Reduce exposure to fraudulent messages |
| Medium | Run targeted, non-punitive phishing awareness exercises | Improve recognition and reporting |
| Medium | Review logging, retention and incident playbooks | Improve evidence quality and repeatability |

**Status:** Proposed improvements for a training scenario, not verified remediations. In a real investigation, each action would require an owner, target date and evidence of completion.

## 8. Lessons learned / reflection

This exercise demonstrates that phishing is not only an email problem: it is also an identity, monitoring and response challenge. An incident response plan provides a structured way to identify an event, contain its impact, recover operations and prevent recurrence. Good reporting avoids unsupported conclusions and makes clear when more evidence is needed.

The purpose of the post-mortem is to improve the organisation's systems and processes rather than assign blame to the employee.

## 9. Portfolio and ethics statement

This report was created to demonstrate my developing incident analysis, documentation and SANS framework knowledge during cybersecurity training. All names, timestamps and actions above are illustrative. It does not contain client information, genuine credentials, phishing links or a claim to have handled a real breach.
