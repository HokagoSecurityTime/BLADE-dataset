from dataclasses import dataclass, fields
@dataclass
class Record:
    id: str
    owner_id: str
    tenant_id: str
    value: str

def ddl():
    return "CREATE TABLE beacon_iot_sensors (" + ", ".join(f.name + " TEXT" + (" PRIMARY KEY" if f.name == "id" else " NOT NULL") for f in fields(Record)) + ");"

if __name__ == "__main__":
    from pathlib import Path
    Path(__file__).with_name("schema.sql").write_text(ddl())
