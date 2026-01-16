import psycopg2
import yaml

DB_CONFIG_PATH = "config/db_config.yaml"

def load_db_config():
    with open(DB_CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
    return config["database"]

def get_db_connection():
    db_config = load_db_config()
    return psycopg2.connect(**db_config)
