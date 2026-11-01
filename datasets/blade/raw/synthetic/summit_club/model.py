from dataclasses import dataclass, fields
@dataclass
class Record:
    id: str
    owner_id: str
    tenant_id: str
    group_id: str
    value: str

@dataclass
class Membership:
    user_id: str
    group_id: str

def ddl():
    rec = "CREATE TABLE summit_club_expeditions (" + ", ".join(f.name + " TEXT" + (" PRIMARY KEY" if f.name == "id" else " NOT NULL") for f in fields(Record)) + ");"
    mem = "CREATE TABLE summit_club_memberships (" + ", ".join(f.name + " TEXT NOT NULL" for f in fields(Membership)) + ", PRIMARY KEY (user_id, group_id));"
    return rec + "\n" + mem

if __name__ == "__main__":
    from pathlib import Path
    Path(__file__).with_name("schema.sql").write_text(ddl())
