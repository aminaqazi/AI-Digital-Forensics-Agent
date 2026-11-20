import os
import pandas as pd

def build_bank_sandbox():
    # 1. Create nested server directories across multiple depths
    folders = [
        "bank_server/public_web",
        "bank_server/dmz/firewall_logs",
        "bank_server/internal/app_server/sessions",
        "bank_server/internal/core_db/backup/archived_2026"
    ]
    for folder in folders:
        os.makedirs(folder, exist_ok=True)

    # 2. Create normal log at shallow depth (Depth 1)
    normal_log = pd.DataFrame([
        {
            "timestamp": "10:15 AM",
            "user": "user_b",
            "target": "public_portal",
            "action": "VIEW",
            "status": "SUCCESS"
        }
    ])
    normal_log.to_csv("bank_server/public_web/access_normal.log", index=False)

    # 3. Hide tampered breach log deep inside nested folders (Depth 4)
    tampered_log = pd.DataFrame([
        {
            "timestamp": "02:00 AM",
            "user": "user_a",
            "target": "credit_cards_db",
            "action": "EXPORT",
            "status": "TAMPERED_LOG"
        }
    ])
    tampered_log.to_csv(
        "bank_server/internal/core_db/backup/archived_2026/audit_hidden.log",
        index=False
    )

    # 4. Create User Permission Table
    permissions = pd.DataFrame([
        {"user": "user_a", "allowed_target": "public_portal"},
        {"user": "user_b", "allowed_target": "public_portal"},
        {"user": "admin_01", "allowed_target": "credit_cards_db"}
    ])
    permissions.to_csv("bank_server/permissions.csv", index=False)

    print("Bank sandbox, hidden logs, and permission table generated successfully!")

if __name__ == "__main__":
    build_bank_sandbox()