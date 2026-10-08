# 🌐 Network Packet Analyzer 🛡️ GUI Tool 👨‍💻

A Python-based desktop **network monitoring and packet analysis application** built using **Tkinter** and **Scapy**. The tool captures and analyzes network packets in real time, displays live traffic statistics, visualizes communication between network hosts, supports PCAP files, and provides basic alerts for potentially suspicious TCP SYN scanning activity.

> ⚠️ **Use Responsibly:** Capture and analyze network traffic only on systems and networks that you own or have explicit permission to monitor.

---

## 🚀 Features

* **Live Packet Capture** 
* **Packet Analysis**
* **Interactive Network Map** 
* **Live Statistics**
* **Threat Alerts** 
* **Packet Filtering** 
* **PCAP Support**
* **Graphical Interface** 
* **Protocol Identification** 
---

## 🛠️ Built With

* **Python 3** - Core programming language.
* **Tkinter** - Graphical user interface (GUI) framework.
* **Scapy** - Packet capture, packet dissection, and network analysis.
* **PCAP** - Standard packet capture format for storing and analyzing network traffic.
* **Graph Visualization** - Used to represent communication between network hosts.

---

## 🖥️ System Architecture

```text
                  ┌───────────────────────────┐
                  │       Main GUI Window     │
                  │   Network Packet Analyzer │
                  └─────────────┬─────────────┘
                                │
                   ┌────────────▼────────────┐
                   │      Packet Capture     │
                   │         Scapy           │
                   └────────────┬────────────┘
                                │
                  ┌─────────────▼─────────────┐
                  │      Packet Processing    │
                  │  Protocol / IP / Port     │
                  │       Identification      │
                  └─────────────┬─────────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
 ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
 │ Live Statistics│    │ Network Graph  │    │ Threat Detection│
 │ & Packet Info  │    │ Visualization  │    │  SYN Activity   │
 └────────────────┘    └────────────────┘    └────────────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                ▼
                    ┌────────────────────────┐
                    │   Analysis / Alerts    │
                    │   PCAP Export / View   │
                    └────────────────────────┘
```

---

## 🖼️ Application Screenshots

### 📊 Main Dashboard

  <img width="1362" height="700" alt="main dashboard" src="https://github.com/user-attachments/assets/f3032f82-45f7-44bc-bd93-b18188441f54" /> 

  ---

### 🔍 Analysis
<img width="1361" height="682" alt="SAMPLE 1" src="https://github.com/user-attachments/assets/03b4ba22-2d48-42f9-81f4-a2734dec9723" />

---

### 🕸️ Graph
<img width="1363" height="682" alt="GRAPH ANALYSIS" src="https://github.com/user-attachments/assets/871cb82e-7989-49c0-a823-649461158138" />

---


## ⚙️ Getting Started

### 📋 Prerequisites

Make sure **Python 3** is installed on your system.

Check your Python installation:

```bash
python --version
```

or:

```bash
python3 --version
```

---

### 📦 Install Dependencies

Install Scapy using:

```bash
pip install scapy
```

---

## 🔵 Windows Setup

Network packet capture on Windows requires a packet-capture driver such as **Npcap**.

Install **Npcap** before running the application.

After installation, run the application with **Administrator privileges** when required for packet capture.

Example:

```bash
python PACKET CAPTURE .py
```

---

## 🐧 Linux Setup

On Linux, packet capture may require elevated privileges.

Run:

```bash
sudo python3 PACKET CAPTURE .py
```

---

## 🍎 macOS Setup

On macOS, packet capture permissions may be required depending on the interface and configuration.

Run the application using the appropriate Python environment and permissions:

```bash
sudo python3 PACKET CAPTURE .py
```

---

## 🔑 Usage Guide

### 1️⃣ Start the Application

Launch the Python application from the terminal or your preferred Python IDE.

```bash
python PACKET CAPTURE .py
```

### 2️⃣ Select Network Interface

Choose the network interface that you want to monitor, if the application provides an interface-selection option.

### 3️⃣ Start Packet Capture

Start the capture process to begin monitoring network traffic.

The application will display captured packets and relevant information in real time.

### 4️⃣ Analyze Packets

Inspect information such as:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Packet length
* TCP flags
* Packet details

### 5️⃣ Monitor Network Activity

Use the live statistics and network graph to understand communication between network hosts.

### 6️⃣ Check Security Alerts

The threat detection component monitors for potentially suspicious TCP SYN activity and generates a basic security alert when relevant activity is detected.

### 7️⃣ Analyze PCAP Files

Load a previously captured `.pcap` file to inspect stored network traffic without performing a new live capture.

---

## 🚨 Threat Detection

The tool contains a **basic detection mechanism for potentially suspicious TCP SYN activity**.

TCP SYN packets are commonly associated with the initial stage of TCP connections. A high volume of SYN requests involving multiple ports or hosts can indicate potentially suspicious scanning behavior.

The tool can generate an alert when activity matches the configured detection conditions.

> ⚠️ **Important:** This is an educational detection mechanism and **not a complete IDS/IPS solution**. Alerts may require further investigation and should not be treated as definitive evidence of an attack.

---

## 📊 Network Monitoring

The application provides several monitoring capabilities:

| Component            | Purpose                                        |
| -------------------- | ---------------------------------------------- |
| 📡 Packet Capture    | Captures network packets in real time          |
| 🔍 Packet Analysis   | Inspects packet and protocol information       |
| 📈 Statistics        | Displays live traffic information              |
| 🌐 Network Map       | Visualizes host-to-host communication          |
| 🚨 Threat Detection  | Identifies potentially suspicious SYN activity |
| 📂 PCAP Support      | Analyzes previously captured traffic           |
| 🎛️ Packet Filtering | Helps focus on relevant traffic                |

---

## 🔐 Security Notice

⚠️ **Only capture and analyze traffic on networks and devices that you own or have explicit permission to monitor.**

This project is intended for:

* 🎓 Cybersecurity education
* 🔬 Network security learning
* 🛠️ Network troubleshooting
* 📊 Packet analysis practice
* 🧪 Authorized security testing
* 🖥️ Python GUI development

Unauthorized packet interception or network monitoring may violate organizational policies or applicable laws.

---

## 🎯 Learning Objectives

This project demonstrates practical concepts including:

* Network packet sniffing
* TCP/IP traffic analysis
* Packet inspection
* Protocol identification
* PCAP file analysis
* Network communication visualization
* Real-time traffic monitoring
* Basic threat detection
* TCP SYN activity analysis
* Python GUI development
* Cybersecurity monitoring

---



## ⭐ Support

If you find this project useful for learning **network security, packet analysis, and cybersecurity monitoring**, consider giving the repository a ⭐.

---

## 👨‍💻 Author

### OM-HERE-09

🔗 **GitHub:**
https://github.com/om-here-09
