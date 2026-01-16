import os

SQL_DIR = "planner"

def load_sql(filename = "query.sql"):
    path = os.path.join(SQL_DIR, filename)
    with open(path, "r") as f:
        return f.read()
