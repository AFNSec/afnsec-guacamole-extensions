# 🛡️ AFNSec Guacamole Extensions

Official binary releases of proprietary **AFNSec** extensions for [Apache Guacamole](https://guacamole.apache.org/).  
These add advanced auditing, visibility, and security capabilities to Guacamole, and are **free to use for personal or internal environments**.

---

## 📘 Overview

This repository provides **pre-compiled `.jar` binaries** built and signed by AFNSec.  
Each extension folder includes its own:

- Compiled extension file  
- SHA-256 checksum manifest  
- Individual README with setup and verification steps  
- License reference  

The extensions are **closed-source** and **not for redistribution, resale, or modification**.  
All are designed to integrate cleanly with standard Apache Guacamole installations.

---

## 📦 Current Release

| Extension | Description | Guacamole Version | Release |
|------------|--------------|------------------|----------|
| **Event Audit** | Structured syslog, JSON, and CEF audit logging for Guacamole sessions. | 1.6.x | 1.0.0 |

See: [`/guacamole-afnsec-event-audit/README.md`](./guacamole-afnsec-event-audit/README.md)

---
## 🗂️ Repository Structure

afnsec-guacamole-extensions/
├─ README.md                     ← This overview
├─ LICENSE.md                    ← Free-use proprietary license
├─ guacamole-afnsec-event-audit/ ← Individual extension folder
│  ├─ README.md                  ← Setup, usage, and verification
│  ├─ guacamole-afnsec-event-audit-1.0.0-guac1.6.jar
│  ├─ SHA256SUMS.txt
│  └─ LICENSE.md (optional copy)
└─ checksums/
└─ SHA256SUMS-v1.0.0.txt

---

## 🧾 License

This software is **free for personal and internal organizational use only**.  
Redistribution, resale, or modification are **not permitted**.

See the full [LICENSE.md](./LICENSE.md).

---

## 🧠 Support & Security

- **Email:** [secops@afnsec.com](mailto:secops@afnsec.com)  
- **Website:** [https://intel.afnsec.com](https://intel.afnsec.com)

Please report security issues privately to the email above.

---

© 2025 **AFNSec** — All rights reserved.