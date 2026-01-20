import psycopg2
import json
from datetime import datetime, timedelta
import os

def reset_database():
    # Database connection parameters
    db_params = {
        "dbname": "vulndb",
        "user": "vulnuser",
        "password": "vulnpass",
        "host": "localhost",
        "port": 5432
    }

    try:
        # 1. Connect to the database
        conn = psycopg2.connect(**db_params)
        conn.autocommit = True  # Required for dropping/creating schemas
        cur = conn.cursor()

        print("Dropping existing schema...")
        # 2. Drop and recreate the public schema (cascades to all tables/indexes)
        cur.execute("DROP SCHEMA public CASCADE;")
        cur.execute("CREATE SCHEMA public;")
        cur.execute("GRANT ALL ON SCHEMA public TO public;")
        cur.execute("GRANT ALL ON SCHEMA public TO vulnuser;") 

        print("Re-running init.sql...")
        # 3. Read and execute your init.sql file
        with open('init.sql', 'r') as f:
            init_script = f.read()
            cur.execute(init_script)

        print("Database reset successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if conn:
            cur.close()
            conn.close()

def update_timestamp(filename, days_in_past=0):
    # 1. Read the file
    with open(filename, 'r') as f:
        data = json.load(f)

    # 2. Update the field (treat 'data' like a standard Python dictionary)
    data['timestamp'] = (datetime.now() - timedelta(days=days_in_past)).isoformat()

    # 3. Write back to the same file
    with open(filename, 'w') as f:
        # indent=4 makes the file human-readable
        json.dump(data, f, indent=4)


def reload_database():

    example_files = [
        'downloaded-artifacts/scan-results-example-1.json',
        'downloaded-artifacts/scan-results-example-2.json',
        'downloaded-artifacts/scan-results-example-3.json',
        'downloaded-artifacts/scan-results-example-4.json',
        'downloaded-artifacts/scan-results-example-5.json',
        'downloaded-artifacts/scan-results-example-6.json',
        'downloaded-artifacts/scan-results-example-7.json',
    ]
    
    for i, file in enumerate(example_files):
        update_timestamp(file, i + 1)

    # Now load the artifacts into the database
    for file in example_files:
        print(f"Loading artifact from file: {file}")
        os.system('python3 scripts/load-artifact-to-database.py ' + file)
    

if __name__ == "__main__":
    reset_database()
    reload_database()