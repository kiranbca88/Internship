"""
run_queries.py
--------------
Helper script to initialize SQLite database (outputs/cyber_incidents.db),
load cleaned CSV data into the schema, execute analytical queries,
and print tabular results to the terminal.
"""

import os
import sqlite3
import pandas as pd

def init_and_run_sql():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    
    csv_path = os.path.join(project_root, "data", "processed", "incidents_cleaned.csv")
    db_path = os.path.join(project_root, "outputs", "cyber_incidents.db")
    schema_path = os.path.join(script_dir, "schema.sql")
    queries_path = os.path.join(script_dir, "analysis_queries.sql")

    if not os.path.exists(csv_path):
        print(f"[ERROR] Processed data not found at {csv_path}. Run data_cleaning.py first.")
        return

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1. Apply Schema
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    cursor.executescript(schema_sql)
    print(f"[SUCCESS] Applied schema to SQLite database at: {db_path}")

    # 2. Load Cleaned CSV Data
    df = pd.read_csv(csv_path)
    df.to_sql("cyber_incidents", conn, if_exists="append", index=False)
    print(f"[SUCCESS] Loaded {len(df)} records into 'cyber_incidents' table.")

    # 3. Read and Execute Queries
    with open(queries_path, "r", encoding="utf-8") as f:
        queries_content = f.read()

    # Split queries by semicolon
    raw_queries = queries_content.split(";")
    query_num = 1
    for raw_q in raw_queries:
        # Strip comments and whitespace
        clean_q = "\n".join([line for line in raw_q.splitlines() if not line.strip().startswith("--")]).strip()
        if not clean_q:
            continue

        print(f"\n========================================================")
        print(f"  SQL QUERY #{query_num}")
        print(f"========================================================")
        try:
            res_df = pd.read_sql_query(clean_q, conn)
            print(res_df.to_string(index=False))
        except Exception as e:
            print(f"[QUERY ERROR]: {e}")
        query_num += 1

    conn.close()
    print("\n[COMPLETE] All analytical SQL queries executed successfully against SQLite.")

if __name__ == "__main__":
    init_and_run_sql()

