import os
import pandas as pd

def depth_limited_search(current_path, current_depth, max_depth, visited_log):
    """Performs a Depth-Limited Search (DLS) up to max_depth."""
    if current_depth > max_depth:
        return None

    visited_log.append((current_depth, current_path))

    # Goal Test: Inspect .log files for tampering markers
    if os.path.isfile(current_path) and current_path.endswith(".log"):
        try:
            df = pd.read_csv(current_path)
            if "status" in df.columns and "TAMPERED_LOG" in df["status"].values:
                return current_path, df
        except Exception:
            pass
        return None

    # Expand child directories/files if within depth limit
    if os.path.isdir(current_path) and current_depth < max_depth:
        for entry in sorted(os.listdir(current_path)):
            child_path = os.path.join(current_path, entry)
            result = depth_limited_search(
                child_path, current_depth + 1, max_depth, visited_log
            )
            if result is not None:
                return result

    return None

def iterative_deepening_search(root_dir, max_limit=10):
    """Iteratively increases the depth limit from 0 up to max_limit."""
    print(f"Starting Iterative Deepening Search on '{root_dir}'...\n")

    for depth_limit in range(max_limit + 1):
        visited = []
        print(f"--- Searching at Depth Limit: {depth_limit} ---")
        result = depth_limited_search(root_dir, 0, depth_limit, visited)
        print(f"Nodes inspected in this iteration: {len(visited)}")

        if result is not None:
            found_path, evidence_df = result
            print(f"\n[ALERT] Tampered log found at Depth {depth_limit}!")
            print(f"File Path: {found_path}\n")
            print("Extracted Breach Record:")
            print(evidence_df.to_string(index=False))
            return found_path, evidence_df

    print("\nNo tampered logs found within maximum depth limit.")
    return None

if __name__ == "__main__":
    iterative_deepening_search("bank_server")