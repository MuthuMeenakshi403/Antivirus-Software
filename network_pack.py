import hashlib
import os
import shutil
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import requests
from PIL import Image, ImageTk


MALWARE_BAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
API_KEY = "3dac84494162a9d817b6c7fa46e12d70"


known_malware_hashes = set()  
cancelled = False  
scan_thread = None  


def fetch_malware_hashes():
    payload = {                   #it is a dictionary handles request by handling recent malware.
        "query": "get_recent",
        "selector": "time"
    }

    try:
        response = requests.post(MALWARE_BAZAAR_API_URL, data=payload)
        response.raise_for_status()  
        data = response.json()
        # print(response.text)
        if data.get('query_status') == 'ok': 
            
            # for entry in data['data']:
            #     print("HASH : " , entry['sha256_hash'])
            return {entry['sha256_hash'] for entry in data['data']}  
        else:
            print("Error: 'data' key is missing or query failed.")
            return set()  
    except requests.exceptions.RequestException as e:
        print("HTTP Request failed:", e)
        return set() 

known_malware_hashes = fetch_malware_hashes()
    
if len(known_malware_hashes) ==0:
    print("NO HASHES FOUND")

print("Recent hashes from malware bazar : ")
for hash in known_malware_hashes:
    print(hash)


def calculate_file_hash(file_path):
    """Calculates and returns the SHA512 hash of the specified file."""
    sha512_hash = hashlib.sha512()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha512_hash.update(byte_block)
        return sha512_hash.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except PermissionError:
        print(f"Permission denied: {file_path}") 
        return None


def check_for_malware(file_hash):
    """Check if the hash exists in the known malware hash set."""
    return file_hash in known_malware_hashes


def quarantine_file(file_path, quarantine_dir='quarantine'):
    """Moves the specified file to a quarantine directory."""
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    try:
        shutil.move(file_path, quarantine_dir)
        print(f"File {file_path} moved to quarantine.")
    except Exception as e:
        print(f"Failed to move {file_path} to quarantine: {e}")


def log_malware(malware_files, log_file='scan_log.txt'):
    """Logs the infected files to a log file."""
    with open(log_file, 'a') as log:
        log.write("Malware scan report:\n")
        for file in malware_files:
            log.write(f"Malware found: {file}\n")
        log.write("End of report.\n\n")
    print(f"Log updated at {log_file}")


def count_files_in_directory(directory):
    """Returns the total number of files in the specified directory."""
    total_files = 0
    for root, dirs, files in os.walk(directory):
        total_files += len(files)
    return total_files


def cancel_scan():
    global cancelled  
    cancelled = True


def scan_directory(directory, infected_files, progress_var, total_files, file_label, result_label):
    global cancelled  
    scanned_files = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            if cancelled:
                result_label.config(text="Scan canceled.")
                progress_bar.stop() 
                return  

            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)

            if file_hash:  
                print(f"Scanning {file_path} (Hash: {file_hash})")
                if check_for_malware(file_hash):
                    print(f"Malware found: {file_path}")
                    infected_files.append(file_path)
                    quarantine_file(file_path)

            
            scanned_files += 1
            progress_var.set((scanned_files / total_files) * 100)
            file_label.config(text=f"Scanning: {file_path}")

            
            if cancelled:
                result_label.config(text="Scan canceled.")
                progress_bar.stop()  
                return  

    if infected_files:
        result_label.config(text=f"Scan complete: {len(infected_files)} malware file(s) found.")
    else:
        result_label.config(text="Scan complete: No malware found.")


def full_system_scan(progress_var, file_label, result_label):
    infected_files = []

    if os.name == 'nt':  
        system_roots = ['C:/', 'D:/', 'E:/']  
    else:
        system_roots = ['/']  
    
    total_files = 0
    for root_dir in system_roots:
        total_files += count_files_in_directory(root_dir)

    
    for root_dir in system_roots:
        scan_directory(root_dir, infected_files, progress_var, total_files, file_label, result_label)

    
    global cancelled
    cancelled = False  

    
    progress_var.set(0)  
    file_label.config(text="Scan completed ")

    if infected_files:
        log_malware(infected_files)
        if not cancelled:
            result_label.config(text=f"Scan complete: {len(infected_files)} malware file(s) found.")
            messagebox.showwarning("Warning", f"Malware detected in {len(infected_files)} files. Files moved to quarantine.")
    else:
        if not cancelled:
            result_label.config(text="Scan complete: No malware found.")
            messagebox.showinfo("Info", "No malware found during full system scan.")


def start_full_scan(progress_var, file_label, result_label):
    global cancelled, scan_thread
    cancelled = False

    if scan_thread and scan_thread.is_alive():
        messagebox.showwarning("Warning", "A scan is already in progress.")
        return

    try:
        
        result_label.config(text="")
        
        
        progress_var.set(0) 
        progress_bar.start(10)  

        
        scan_thread = threading.Thread(target=full_system_scan, args=(progress_var, file_label, result_label))
        scan_thread.start()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during the scan: {e}")


def create_gui():
    app = tk.Tk()
    app.title("SecureScan Antivirus")

    
    app.geometry("800x600")

    
    background_image = Image.open("bg.png")  
    background_image = background_image.resize((800, 600), Image.LANCZOS)  
    background_photo = ImageTk.PhotoImage(background_image)

    
    background_label = tk.Label(app, image=background_photo)
    background_label.place(relwidth=1, relheight=1)  

    
    widget_frame = tk.Frame(app, bg="white", bd=2)
    widget_frame.place(relx=0.5, rely=0.5, anchor='center')

    
    global progress_bar  
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(widget_frame, variable=progress_var, maximum=100)
    progress_bar.pack(pady=10)

    
    file_label = tk.Label(widget_frame, text="Scanning...", bg="white")
    file_label.pack(pady=5)

    
    result_label = tk.Label(widget_frame, text="", bg="white")
    result_label.pack(pady=5)

    
    start_button = tk.Button(widget_frame, text="Start Full Scan", command=lambda: start_full_scan(progress_var, file_label, result_label))
    start_button.pack(pady=5)

    
    cancel_button = tk.Button(widget_frame, text="Cancel Scan", command=cancel_scan)
    cancel_button.pack(pady=5)

    
    exit_button = tk.Button(widget_frame, text="Exit", command=app.quit)
    exit_button.pack(pady=5)

    app.mainloop()


if __name__ == "__main__":
    create_gui()
    