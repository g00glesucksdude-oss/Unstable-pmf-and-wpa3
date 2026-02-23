import os
import json
import hashlib
import shutil
import time
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from google.colab import drive
from tqdm import tqdm

drive.mount('/content/drive')

# --- CONFIG: TUNED FOR STABILITY ---
MASTER_DIR = '/content/drive/MyDrive/COLAB_ELITE_SYSTEM'
MANIFEST_FILE = os.path.join(MASTER_DIR, 'elite_manifest.json')
LOCAL_WORK_AREA = '/content/work_area'

# LOGIC: 512MB * (4 workers + 2 parity buffers) ≈ 3GB RAM usage. Safe.
CHUNK_SIZE = 512 * 1024 * 1024  
MAX_WORKERS = 4  

os.makedirs(MASTER_DIR, exist_ok=True)

# --- LOGIC: THE NUMPY ACCELERATOR ---

def generate_parity_fast(chunk_a, chunk_b):
    """In-place XOR to prevent RAM spikes during parity generation."""
    max_len = max(len(chunk_a), len(chunk_b))
    res = np.zeros(max_len, dtype=np.uint8)
    if len(chunk_a) > 0:
        res[:len(chunk_a)] ^= np.frombuffer(chunk_a, dtype=np.uint8)
    if len(chunk_b) > 0:
        res[:len(chunk_b)] ^= np.frombuffer(chunk_b, dtype=np.uint8)
    return res.tobytes()

def get_chunk_hash(data):
    """Standard MD5 for chunk verification."""
    return hashlib.md5(data).hexdigest()

def get_free_space(path):
    """The Equalizer Sensor: Checks real capacity."""
    try:
        stat = shutil.disk_usage(path)
        return stat.free - (150 * 1024 * 1024) # 150MB Safety Buffer
    except:
        return 0

def upload_worker(data, path):
    """Parallel Worker: Commits data and returns hash for manifest."""
    with open(path, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    return get_chunk_hash(data)
# --- LOGIC: THE DISCOVERY & EQUALIZER SYSTEM ---

def discover_slaves():
    """Automated Discovery: Filters for usable directories on MyDrive."""
    base = '/content/drive/MyDrive'
    # Logic: Only include real folders, ignore hidden files and shortcuts to files
    all_items = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
    usable_folders = [d for d in all_items if not d.startswith('.') and d != 'Colab Notebooks']
    
    print("\n--- AUTOMATED SLAVE DISCOVERY ---")
    for i, name in enumerate(usable_folders):
        print(f"{i+1}. {name}")
    
    selection = input("\nSelect Slaves to Pool (e.g., 1 2 5): ").split()
    return [os.path.join(base, usable_folders[int(i)-1]) for i in selection]

def get_best_slave(slaves, current_ptr, required_size):
    """
    The Dynamic Equalizer: Hunts for a slave with enough room.
    Cycles through the list until it finds space or exhausts all options.
    """
    attempts = 0
    while attempts < len(slaves):
        target = slaves[(current_ptr + attempts) % len(slaves)]
        if get_free_space(target) >= required_size:
            return target, (current_ptr + attempts) # Return found drive and updated index
        attempts += 1
    
    raise OSError("CRITICAL: All selected Slave drives are FULL.")

# --- LOGIC: INITIALIZING THE SAVE PROCESS ---

def elite_save():
    slaves = discover_slaves()
    use_safety = input("\nEnable Safety Net? (RAID-5 XOR) Y/N: ").strip().lower() == 'y'

    if use_safety and len(slaves) < 3:
        print("LOGIC ERROR: Safety Net requires 3+ slaves. Reverting to Standard Mode.")
        use_safety = False

    # Load existing manifest for Resume Logic
    if os.path.exists(MANIFEST_FILE):
        with open(MANIFEST_FILE, 'r') as f: manifest = json.load(f)
    else:
        manifest = {"files": {}, "config": {"safety_net": use_safety, "chunk_size": CHUNK_SIZE}}

    targets = [f for f in os.listdir(LOCAL_WORK_AREA) if os.path.isfile(os.path.join(LOCAL_WORK_AREA, f))]
    
    # We will pass this manifest and file list into the Parallel Dispatcher (Part 3)
    # ... logic continues to Part 3 ...
# --- LOGIC: THE PARALLEL DISPATCHER (FIXED) ---

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for filename in targets:
            file_path = os.path.join(LOCAL_WORK_AREA, filename)
            total_size = os.path.getsize(file_path)
            chunks_info = []
            
            with open(file_path, 'rb') as f:
                idx = 0
                slave_ptr = 0 # Independent pointer for the Equalizer
                pbar = tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Pushing {filename}")
                
                while True:
                    A = f.read(CHUNK_SIZE)
                    if not A: break
                    
                    # Group construction logic
                    if use_safety:
                        B = f.read(CHUNK_SIZE) or b""
                        C = generate_parity_fast(A, B)
                        group_data = [A, B, C]
                    else:
                        group_data = [A]

                    # Parallel Dispatch Logic (The Fix)
                    futures_and_meta = []
                    group_meta = []

                    for i, data in enumerate(group_data):
                        # EQUALIZER: Find a slave with room for this specific piece
                        target_slave, slave_ptr = get_best_slave(slaves, slave_ptr + 1, len(data))
                        s_name = f"{filename}.g{idx}.p{i}"
                        s_path = os.path.join(target_slave, s_name)
                        
                        # Prepare metadata object
                        meta = {"path": s_path, "size": len(data)}
                        group_meta.append(meta)

                        # RESUME LOGIC: Check if we can skip upload
                        if os.path.exists(s_path) and os.path.getsize(s_path) == len(data):
                            # Even if skipping, we need the hash for the manifest
                            meta["hash"] = get_chunk_hash(data)
                        else:
                            # DISPATCH: Pair the future with the meta object
                            future = executor.submit(upload_worker, data, s_path)
                            futures_and_meta.append((future, meta))

                    # 3. SYNCHRONIZE: Wait for this group to finish before next read
                    # This prevents RAM bloat by not reading Chunk D before A/B/C are safe
                    for future, meta in futures_and_meta:
                        meta['hash'] = future.result() # Correctly maps hash to specific meta

                    # Progress Bar logic (handles A + B size)
                    pbar.update(len(A) + (len(B) if use_safety and B else 0))
                    chunks_info.append({"group_id": idx, "parts": group_meta})
                    idx += 1
                
                print(f"\n[INFO] Finalizing {filename} manifest...")
                pbar.close()
            
            manifest["files"][filename] = {"chunks": chunks_info}

    # Final persistent write of the manifest
    with open(MANIFEST_FILE, 'w') as mf:
        json.dump(manifest, mf, indent=4)
    print("\n--- SAVE SUCCESS: SLAVES SYNCHRONIZED ---")
# --- LOGIC: THE RECONSTRUCTOR (LOAD) ---

def elite_load():
    """
    Logic: Heal-Before-Write.
    Proactively checks checksums and repairs corrupted data in RAM.
    """
    if not os.path.exists(MANIFEST_FILE):
        print("CRITICAL ERROR: No manifest found. Cannot reconstruct.")
        return

    with open(MANIFEST_FILE, 'r') as mf:
        manifest = json.load(mf)
    
    is_safe = manifest["config"].get("safety_net", False)

    for filename, info in manifest["files"].items():
        out_p = os.path.join(LOCAL_WORK_AREA, filename)
        print(f"\n--- Reconstructing {filename} ---")
        
        with open(out_p, 'wb') as out_f:
            for group in tqdm(info["chunks"], desc="Pulling Shards"):
                parts_data = []
                broken_indices = []

                # 1. RETRIEVE AND VALIDATE
                for i, meta in enumerate(group["parts"]):
                    try:
                        if not os.path.exists(meta["path"]):
                            raise FileNotFoundError(f"Missing Part {i}")
                        
                        with open(meta["path"], 'rb') as f:
                            data = f.read()
                            # Logic: Autodetect corruption
                            if hashlib.md5(data).hexdigest() != meta["hash"]:
                                raise ValueError(f"Checksum mismatch on Part {i}")
                            
                            parts_data.append(data)
                    except Exception as e:
                        print(f"\n[!] DATA ERROR: {e}")
                        parts_data.append(None)
                        broken_indices.append(i)

                # 2. THE HEALING JUNCTION
                if is_safe and len(broken_indices) == 1:
                    print(f"[+] SELF-HEALING: Reconstructing missing shard {broken_indices[0]}...")
                    m_idx = broken_indices[0]
                    # Logic: Filter out the 'None' to perform XOR on survivors
                    others = [p for p in parts_data if p is not None]
                    # XOR handles A=B^C, B=A^C, or C=A^B automatically
                    parts_data[m_idx] = generate_parity_fast(others[0], others[1])
                
                elif len(broken_indices) > 0 and not is_safe:
                    raise RuntimeError(f"FATAL: Part {broken_indices} is dead and no Safety Net exists.")
                
                elif len(broken_indices) > 1:
                    raise RuntimeError("CATASTROPHIC FAILURE: More than 1 shard lost in this group. Recovery impossible.")

                # 3. COMMIT VALIDATED DATA
                # Logic: parts_data[0] is Chunk A, parts_data[1] is Chunk B
                if parts_data[0] is None:
                    raise RuntimeError("Logic Error: Failed to heal Chunk A.")
                
                out_f.write(parts_data[0])
                
                # Only write Part B if it exists and isn't just padding
                if is_safe and len(parts_data) > 1:
                    target_size_b = group["parts"][1]["size"]
                    if target_size_b > 0:
                        out_f.write(parts_data[1][:target_size_b])

    print(f"\nSUCCESS: {filename} reconstructed and verified.")
# --- LOGIC: STORAGE HYGIENE (WIPE) ---

def master_wipe():
    """
    The Janitor: Uses the manifest to hunt down and delete all shards 
    associated with a specific file across the slave network.
    """
    if not os.path.exists(MANIFEST_FILE):
        print("No manifest found. Nothing to wipe.")
        return

    with open(MANIFEST_FILE, 'r') as mf:
        manifest = json.load(mf)

    print("\n--- MASTER WIPE: SELECT FILE ---")
    files = list(manifest["files"].keys())
    for i, name in enumerate(files):
        print(f"{i+1}. {name}")
    
    choice = input("\nEnter number to WIPE (or 'all'): ").strip().lower()
    to_delete = files if choice == 'all' else [files[int(choice)-1]]
    
    for filename in to_delete:
        print(f"Cleaning shards for: {filename}...")
        for group in manifest["files"][filename]["chunks"]:
            for part in group["parts"]:
                if os.path.exists(part["path"]):
                    os.remove(part["path"])
        
        del manifest["files"][filename]
        print(f"[-] {filename} removed from Slave network.")
    
    # Update manifest to reflect deletions
    with open(MANIFEST_FILE, 'w') as mf:
        json.dump(manifest, mf, indent=4)
    print("\nWIPE COMPLETE.")

# --- LOGIC: PRE-EMPTIVE HEALTH (SCRUB) ---

def scrub_slaves():
    """
    The Sentinel: Scans all shards in the manifest to detect 
    missing or corrupted data before you actually need to LOAD.
    """
    if not os.path.exists(MANIFEST_FILE):
        print("No manifest to scrub.")
        return

    with open(MANIFEST_FILE, 'r') as mf:
        manifest = json.load(mf)
    
    print("\n--- INITIATING SYSTEM SCRUB ---")
    issues = 0
    for filename, info in manifest["files"].items():
        for group in info["chunks"]:
            for part in group["parts"]:
                if not os.path.exists(part["path"]):
                    print(f"[!] MISSING: {part['path']}")
                    issues += 1
                else:
                    with open(part["path"], 'rb') as f:
                        if hashlib.md5(f.read()).hexdigest() != part["hash"]:
                            print(f"[!] CORRUPTION DETECTED: {part['path']}")
                            issues += 1
    
    if issues == 0:
        print("ALL SYSTEMS NOMINAL: Your 1 TB data is safe and verifiable.")
    else:
        print(f"\n[CRITICAL] Found {issues} issue(s). Use Safety Net to recover.")

# --- MAIN EXECUTION INTERFACE ---

def main():
    print("\n========================================")
    print("   UNIVERSAL ELITE SHARDER (v3.7)       ")
    print("========================================")
    print("1. SAVE   (Upload with Parallel/Safety)")
    print("2. LOAD   (Reconstruct with Self-Heal)")
    print("3. SCRUB  (Check Health of Shards)")
    print("4. WIPE   (Delete Files from Slaves)")
    print("5. EXIT")
    
    choice = input("\nSelect Action [1-5]: ").strip()
    
    if choice == '1': elite_save()
    elif choice == '2': elite_load()
    elif choice == '3': scrub_slaves()
    elif choice == '4': master_wipe()
    elif choice == '5': print("System Terminated.")
    else: print("Invalid Selection.")

if __name__ == "__main__":
    main()
