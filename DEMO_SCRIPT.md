# 🎤 SecuriSphere Demo Script

**Target Audience**: Stakeholders, Instructors, or Technical Peers.
**Goal**: Demonstrate SecuriSphere's ability to detect, correlate, and visualize multi-stage cyber attacks in real-time.

---

## 🕒 Pre-Demo Setup (5 Mins Before)
1. **Reset Environment**: Ensure a clean state.
   ```bash
   make reset
   make setup
   make start
   ```
2. **Open Dashboard**: Load [http://localhost:3000](http://localhost:3000) in Chrome/Edge.
3. **Verify Health**: Check that all systems are green in the "System Health" widget.
4. **Open Terminal**: Have a terminal window ready, navigated to the project root.

---

## 🎬 The Demo Flow

### 1. Introduction (1 Minute)
**Narrator**: "Welcome to the SecuriSphere demonstration. Modern applications face complex threats that bypass traditional single-layer defenses. Today, I'll show you how SecuriSphere uses multi-layer monitoring and correlation to detect sophisticated attacks."

**Action**: Show the Dashboard "Overview" tab. Point out the empty "Active Risk Entities" and "Recent Incidents" sections – "The system is currently quiet and monitoring."

---

### 2. Scenario A: Benign User Traffic (2 Minutes)
**Narrator**: "First, let's establish a baseline. Security tools often suffer from false positives—alerting on normal behavior. We'll simulate regular user traffic: browsing products, logging in, and searching."

**Action**:
1. Run in terminal: `make attack-benign`
2. Switch to Dashboard.

**Narrator**: "You can see 'Raw Events' appearing in the Live Feed—successful logins, page views. Notice the Risk Scores. They remain low (Green). Crucially, **Zero Incidents** are created. This proves SecuriSphere differentiates between normal usage and attacks."

---

### 3. Scenario B: The 'Stealth' Scan (2 Minutes)
**Narrator**: "Now, an attacker attempts a 'low-and-slow' probe. They execute a single, high-severity SQL Injection attempt, trying to stay under the radar of frequency-based detection."

**Action**:
1. Run in terminal: `make attack-stealth`
2. Watch Dashboard.

**Visuals**:
- A single Critical event appears in the feed.
- **Incident Generated**: "Critical Exploit Attempt".
- **Risk Score**: Spikes immediately for the attacker's IP.

**Narrator**: "Even though this was just a few requests, our correlation engine identified the *Critical* nature of the payload (SQLi) and immediately flagged it. Traditional rate-limiting would have missed this."

---

### 4. Scenario C: Full Kill Chain (The Grand Finale) (3 Minutes)
**Narrator**: "Finally, we'll demonstrate a full kill chain. The attacker will move through Reconnaissance, Brute Force, Exploitation, and finally Data Exfiltration. Watch how the Risk Score escalates."

**Action**:
1. Run in terminal: `make attack-killchain`
2. **NARRATE AS IT HAPPENS (Watch the Dashboard):**

- **Stage 1 (Recon)**: "First, Port Scanning. See the Network events? Risk score starts climbing (Low)."
- **Stage 2 (Brute Force)**: "Now, failed login attempts at the Auth layer. The Engine correlates these with the scan -> Incident: 'Recon followed by Auth Attack'."
- **Stage 3 (Exploit)**: "They found a credential (admin/admin123). Now they attack the API. SQL Injection detected!"
- **Stage 4 (Exfiltration)**: "They are downloading the user database. Alert: 'Data Exfiltration detected'."

**Conclusion**: "The dashboard now shows a 'Critical' threat level for the attacker IP. We successfully tracked the attack across Network, Auth, and API layers, correlating it into a single actionable narrative."

---

### 5. Q&A and Wrap Up
**Narrator**: "SecuriSphere unified 20+ raw events into 3 distinct, prioritized incidents, giving analysts the full context needed to respond. Thank you."

---

## 🛑 Troubleshooting During Demo
- **Dashboard not updating?**: Refresh the page (F5).
- **No events appearing?**: Check backend logs: `make logs-backend`.
- **Attack script failed?**: Run `make restart` and try again.
