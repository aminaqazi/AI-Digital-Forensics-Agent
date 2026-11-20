import pandas as pd
from pyswip import Prolog
from ids_search import iterative_deepening_search

def run_forensic_analysis():
    prolog = Prolog()
    prolog.consult("forensics_rules.pl")

    # 1. Load user permissions into Prolog knowledge base
    perms_df = pd.read_csv("bank_server/permissions.csv")
    for _, row in perms_df.iterrows():
        prolog.assertz(f"permitted('{row['user']}', '{row['allowed_target']}')")

    # 2. Retrieve tampered log via Week 1 IDS crawler
    result = iterative_deepening_search("bank_server")
    if not result:
        print("No breach log found to analyze.")
        return

    _, evidence_df = result
    for _, row in evidence_df.iterrows():
        prolog.assertz(
            f"log_event('{row['timestamp']}', '{row['user']}', "
            f"'{row['target']}', '{row['action']}', '{row['status']}')"
        )

    # 3. Query Prolog inference rules
    print("\n=== PROLOG SYMBOLIC FORENSICS VERDICT ===")
    for breach in prolog.query("critical_breach(User, Target)"):
        print(f"[CRITICAL BREACH] User '{breach['User']}' compromised '{breach['Target']}'")
    for unauth in prolog.query("unauthorized_access(User, Target)"):
        print(f" - Rule Triggered: Unauthorized access by '{unauth['User']}' on '{unauth['Target']}'")
    for tampered in prolog.query("log_tampered(User, Target)"):
        print(f" - Rule Triggered: Audit log tampering detected for '{tampered['User']}'")
    for exfil in prolog.query("suspicious_exfiltration(User, Target)"):
        print(f" - Rule Triggered: Off-hours data export (02:00 AM) by '{exfil['User']}'")

if __name__ == "__main__":
    run_forensic_analysis()