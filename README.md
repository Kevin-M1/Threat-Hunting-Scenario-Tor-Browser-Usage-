# Threat-Hunting-Scenario-Tor-Browser-Usage-
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Kevin-M1/Threat-Hunting-Scenario-Tor-Browser-Usage-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called tor-shopping-list.txt on the desktop. These events began at 2025-03-30T13:38:05.4330989Z
Query to locate events:



**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "kvm-vm"
| where InitiatingProcessAccountName == "kevin0715"
| where FileName  contains "tor"
| where Timestamp >= datetime(2025-03-30T13:38:05.4330989Z)
| order by Timestamp desc
|project Timestamp,DeviceName,ActionType,FileName,FolderPath,SHA256, InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/3a6e83c2-08c2-4b0e-a423-47b82365749e)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched DeviceProcessEvents table for any ProcessCommandLine that contained the string "Tor-browser-windows-x86_64-portable-14.0.8.exe" Based on the logs returned
2025-03-30T13:44:49.2598123Z, user kevin0715 on device kvm-vm silently launched the Tor Browser portable installer from their Downloads folder, executing the file tor-browser-windows-x86_64-portable-14.0.8.exe with a /S (silent) command.




**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "kvm-vm"
|where ProcessCommandLine contains"tor-browser-windows-x86_64-portable-14.0.8.exe"
|project Timestamp,DeviceName,AccountName, ActionType, FileName,FolderPath,SHA256,ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/0275c589-9ca2-4907-a834-9a64c1aa4dd8)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user ”Kevin0715” actually opened the tor browser. There was evidence that they did open it at 2025-03-30T13:58:41.2790641Z. There were several other instances of firefox.exe (TOr) as well as tor.exe spawned afterwords



**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName =="kvm-vm"
|where FileName has_any( "tor.exe","firefox.exe","tor-browser.exe")
|project Timestamp,DeviceName,AccountName,ActionType,FileName,FolderPath,SHA256,ProcessCommandLine
|order by Timestamp desc


```
![image](https://github.com/user-attachments/assets/d48fc701-a669-4034-9a3e-14a2144f2bfd)




---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor port numbers 2025-03-30T14:00:59.4493507Z, user kevin0715 on device kvm-vm successfully established an outbound connection from tor.exe—located in the Tor Browser directory on their desktop—to the external IP address 104.152.111.1 over port 443, indicating the Tor service was actively connecting to the internet. There were a couple of other connections to sites over port 9150


**Query used to locate events:**

```kql
Query used to locate events 
  DeviceNetworkEvents  
| where DeviceName == "kvm-vm"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/2e591a62-589f-45c4-9c43-6781911a7dd0)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
