# **Advanced Keylogger with Remote Access Monitoring**

This **Advanced Keylogger with Remote Access Monitoring** is a robust Python-based system designed to track and log user activity efficiently. It operates silently in the background, capturing all keystrokes along with active window titles, while simultaneously monitoring for potential remote access threats. The keylogger ensures real-time data logging, making it an essential tool for security analysis, system monitoring, and forensic investigations.  

## **🔹 Key Features**  
### **1️⃣ Keystroke Logging**  
- Captures all keyboard inputs, including special keys.  
- Logs the title of the active window where the keystrokes occur.  
- Saves data with timestamps for accurate activity tracking.  

### **2️⃣ Remote Access Detection**  
- Monitors active network connections for Remote Desktop Protocol (RDP) sessions.  
- Detects known remote access software such as **TeamViewer, AnyDesk, and VNC**.  
- Logs all remote access attempts with timestamps for later analysis.  

### **3️⃣ Automated Reporting System**  
- Generates structured reports every 15 minutes, summarizing user activity.  
- Stores logs in well-organized directories for easy retrieval.  
- Press **'Z'** to view the latest report in a graphical interface.  
- Press **'A'** to close the report window.  

### **4️⃣ Background Execution & Persistence**  
- Runs in the background without interfering with user activities.  
- Can be set up as a **Windows Service** for continuous monitoring.  
- Ensures logs remain intact even after a system restart.  

### **5️⃣ Secure and Reliable Logging**  
- Stores keystrokes and remote access logs in encrypted text files.  
- Automatically detects unauthorized system access and generates alerts.  
- Uses multithreading for efficient monitoring without performance lag.  

## **🛠️ How It Works**  
1. The script starts by initializing all required log files and directories.  
2. A **keyboard listener** records every key press along with the active window title.  
3. A **network monitor** continuously checks for remote access attempts.  
4. Reports are generated automatically every 15 minutes and stored for analysis.  
5. Users can manually view reports anytime by pressing **'Z'** and close the report window with **'A'**.  

## **⚡ Why Use This Keylogger?**  
- **Efficient & Lightweight** – Minimal CPU and memory usage.  
- **Real-time Monitoring** – Provides live keystroke and remote access tracking.  
- **Automated Reports** – No manual intervention needed for generating logs.  
- **Security Focused** – Helps detect unauthorized remote access attempts.  

## **🚀 Installation & Setup**  
To run this keylogger, install the required dependencies:  
```bash
pip install pynput psutil pywin32
```  
Then, execute the script:  
```bash
python keylogger.py
```  
To run it as a **Windows Service**, use the included `keylogger_service.bat` file.  

## **⚠️ Disclaimer**  
This software is intended **strictly for ethical use**. Unauthorized use to track keystrokes on a system without the owner’s consent may be illegal. Use it responsibly and only in compliance with local laws.  

---  

### 📌 Author: TIPU REHMAN
