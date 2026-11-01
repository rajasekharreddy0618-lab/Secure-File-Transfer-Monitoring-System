# FINAL SECURITY AUDIT REPORT - SECURE FILE TRANSFER MONITORING SYSTEM
**Generated On:** 2026-11-01 11:53:17
**Monitored Endpoint:** `SecOps-Workstation-01`

## 1. Executive Summary Metrics
- **Total File Events Monitored:** 42
- **Sensitive File Events:** 3
- **Policy / Authorization Violations:** 3
- **File Integrity Failures (Hash Mismatches):** 1

## 2. Triggered Security Alerts
1. **[2026-11-01 11:53:12]** `Alert: Sensitive file copied to USB drive` (File: `salary_data.csv`)
2. **[2026-11-01 11:53:12]** `Alert: Sensitive file copied to USB drive` (File: `salary_data.csv`)
3. **[2026-11-01 11:53:13]** `Integrity Failure: File hash mismatch detected` (File: `salary_data.csv`)

## 3. Recent File Activity Audit Trail (Sample)
| Timestamp | Event | Classification | Source Path | Destination Path | User | Process | Integrity | Auth Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-11-01 11:53:12 | COPY | SENSITIVE | `monitored_zone/sensitive_vault/salary_data.csv` | `monitored_zone/simulated_usb/salary_data.csv` | SecOps_Admin (Raju) | Code.exe | VERIFIED (Match) | SUSPICIOUS / VIOLATION |
| 2026-11-01 11:53:12 | MODIFY | SENSITIVE | `monitored_zone/simulated_usb/salary_data.csv` | `monitored_zone/simulated_usb/salary_data.csv` | SecOps_Admin (Raju) | Code.exe | VERIFIED (Match) | SUSPICIOUS / VIOLATION |
| 2026-11-01 11:53:13 | MODIFY | SENSITIVE | `monitored_zone/sensitive_vault/salary_data.csv` | `monitored_zone/sensitive_vault/salary_data.csv` | SecOps_Admin (Raju) | Code.exe | INTEGRITY_FAILURE | SUSPICIOUS / VIOLATION |
| 2026-11-01 11:53:15 | CREATE / DOWNLOAD | NORMAL | `monitored_zone/unknown_directory/exfil_record_1.tmp` | `monitored_zone/unknown_directory/exfil_record_1.tmp` | SecOps_Admin (Raju) | Code.exe | VERIFIED (New Baseline) | ALLOWED |
| 2026-11-01 11:53:15 | MODIFY | NORMAL | `monitored_zone/unknown_directory/exfil_record_1.tmp` | `monitored_zone/unknown_directory/exfil_record_1.tmp` | SecOps_Admin (Raju) | Code.exe | VERIFIED (Match) | ALLOWED |