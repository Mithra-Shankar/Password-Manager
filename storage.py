# storage.py
import json
import os
import base64
# NOTE: The encryption module is imported in main.py, but not needed here for Caesar key management

DATA_FILE = "passwords.json"
MASTER_FILE = "master.key"

def load_data():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def master_exists():
    return os.path.exists(MASTER_FILE)

def create_master_password(password):
    master_hash = base64.urlsafe_b64encode(password.encode()).decode()
    with open(MASTER_FILE, "w") as f:
        f.write(master_hash)
    
    save_data([])

def verify_master_password(password):
    if not master_exists():
        return False
    
    with open(MASTER_FILE, "r") as f:
        master_hash = f.read()
    
    return master_hash == base64.urlsafe_b64encode(password.encode()).decode()

def get_all_entries():
    return load_data()

def add_entry(website, username, encrypted_password):
    data = load_data()
    new_id = (data[-1]["id"] + 1) if data else 1 
    data.append({
        "id": new_id,
        "website": website,
        "username": username,
        "password": encrypted_password
    })
    save_data(data)

def delete_entry(entry_id_str):
    try:
        entry_id = int(entry_id_str)
    except ValueError:
        return
        
    data = load_data()
    data = [entry for entry in data if entry.get("id") != entry_id]
    
    for i, entry in enumerate(data):
        entry['id'] = i + 1
        
    save_data(data)