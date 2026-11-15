# ASTRA-MED — Autonomous Spaceflight Triage & Astronaut Health OS

**2026 NASA Space Apps Challenge:** *Create Health Monitoring Software for Astronauts on Space Missions*

ASTRA-MED is an offline-first, zero-trust 3D astronaut biometric monitoring and autonomous diagnostic platform designed for long-duration lunar (Artemis) and Mars missions where Earth communication delays prevent real-time flight surgeon intervention.

---

## Judge Quick-Start & Demo Credentials
* **NASA-Provisioned Crew ID:** `NASA-ARTEMIS-04`
* **Default Passkey:** `ORION-2026`
* **Frontend Launch:** Open `index.html` directly in any modern browser (automatically runs in air-gapped browser vault mode).
* **Full-Stack Backend Launch (Optional):** Run `python app.py` to activate the hardened Python API (`http://127.0.0.1:8080`), encrypted SQLite biometric vault (`astramed_vault.db`), and tamper-evident SHA-256 audit chain.

---

## Core Capabilities & NASA HRP Alignment
1. **Interactive 3D Holographic Anatomy HUD (Three.js):** Clickable organ and suit systems (*Brain & Neuro, Cardiovascular, Lungs & Cabin, Bone Density, Radiation Shield*) synchronized with color-coded Green/Amber/Red triage alerts.
2. **NASA 5 Spaceflight Hazards Coverage:** Tracks Space Radiation, Isolation & Confinement, Distance from Earth (up to 22-min Mars comms delay), Altered Gravity Fields, and Hostile Closed Environments.
3. **Live Webcam rPPG Pulse & Fatigue Scanner:** Browser-local optical pulse extraction (`getUserMedia`) with zero cloud video transmission.
4. **Symptom-Driven Nutrition, Hydration & Zero-G Exercise Engine:** Dynamically adjusts daily water targets (mL/sol), space ration micronutrients, and ARED/T2/CEVIS workouts based on active symptoms.
5. **Offline AI Flight Surgeon Co-Pilot & Voice Commands:** Hands-free Web Speech voice navigation and plain-language medical triage (e.g., SANS fluid shift, dehydration, solar storm protocols).
6. **xEMU EVA Suit Telemetry & Emergency Trigger:** Dedicated EVA suit thermal/battery/pressure monitoring and a 1-click Red-Alert Emergency Distress Beacon.

---

## High-Level Security & Governance Architecture
* **NASA-Only IAM Provisioning:** Public registration is disabled; astronauts may rotate only their passkey while the NASA Crew ID remains permanently locked.
* **Cryptographic Auth & Storage:** PBKDF2-SHA256 / PBKDF2-HMAC-SHA512 hashing, brute-force lockout protection, 15-minute idle auto-lock, Fernet/AES-GCM encryption at rest, and a SHA-256 hash-chained audit ledger.
* **Open-Source License:** Released under the **MIT License**.

---

## NASA & Space Agency Resources Cited
* **NASA Human Research Program (HRP):** *Risks of Human Spaceflight* & *Ongoing HRP Research in Space* (5 Spaceflight Hazards framework and clinical telemetry thresholds).
* **Canadian Space Agency (CSA):** *Monitoring Radiation for Astronaut Health* (cumulative radiation exposure and solar particle event protocols).
