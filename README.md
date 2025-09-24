# 🛰️ Network Tools with GUI

A simple yet powerful **Network Tools Application** with a clean **PyQt5 GUI**, built in Python.  
This app provides multiple networking utilities in one place: **Ping, Traceroute, Port Scanner, Speedtest, and WHOIS Lookup**.  

---

## ✨ Features

- **Ping Host** → Test latency and packet loss to any domain/IP.  
- **Traceroute** → Show network path (hops) to target host.  
- **Port Scanner** → Scan open/closed ports on a given IP/domain.  
- **Speedtest** → Check internet download & upload speed (powered by `speedtest-cli`).  
- **WHOIS Lookup** → Fetch WHOIS information for a domain.  
- **Auto IP Detection**:
  - If no host/IP is entered, the app automatically detects **Public IP** and **Local IP**.  
  - Public IP is fetched via API (`https://api.ipify.org`), Local IP via socket.  
  - User can choose which IP to test against (default: Public → fallback Local).  
- **Logging** → All actions are logged using rotating log files (`logs/network_tools.log`).  
- **Persistent Settings** → User preferences saved automatically with `QSettings`.  
- **Threaded Operations** → Network operations run in background threads so the UI never freezes.  
- **Export Results** → Test results can be copied or saved as `.txt` for later use.  

---

## 📂 Project Structure

```
tools/
│── main.py          # Entry point of the application
│── ui.py            # GUI built with PyQt5
│── network_ops.py   # Networking functions (ping, traceroute, port scan, etc.)
│── settings.py      # Settings manager with QSettings
│── logger.py        # Logging configuration
│── requirements.txt # Dependencies
```

---

## 🔧 Requirements

- Python **3.8+**
- Dependencies:
  - PyQt5 >= 5.15  
  - requests >= 2.25  
  - speedtest-cli >= 2.1.3  
  - python-whois >= 0.7.3  

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## ▶️ How to Run

1. **Clone the repository**:

```bash
git clone https://github.com/Kyzosan/SPEED-TEST
cd SPEED-TEST
```

2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

3. **Run the app**:

```bash
python main.py
```

---

## 📸 Screenshots

_Add screenshots here (optional)._  

Example UI: Tabs for **Ping, Traceroute, Port Scanner, Speedtest, WHOIS** with log output and status bar showing detected IPs.

---

## ⚙️ Configuration

- **Logs** → stored in `logs/network_tools.log`. Rotated automatically (max 5 files, 5 MB each).  
- **Settings** → automatically saved in system config (`QSettings`).  
- **Default Behavior** → If input is empty, app tries to detect Public IP (fallback Local IP).  

---

## 🛠️ Development Notes

- Modular design → UI (`ui.py`) separated from logic (`network_ops.py`).  
- Long-running tasks use **QThread / ThreadPoolExecutor**.  
- Error handling ensures app doesn't freeze if host is unreachable or request times out.  
- Results can be copied or exported to file.  
- Easy to extend with new tools (e.g., DNS lookup, HTTP header fetch).  

---

## 🤝 Contributing

Contributions are welcome!  
Steps:  
1. Fork this repository.  
2. Create a new branch (`feature/my-feature`).  
3. Commit your changes.  
4. Push to your fork.  
5. Open a Pull Request.  

Please open issues for bugs/feature requests.  

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 🙌 Credits

Developed by **Your Name** (replace with your GitHub username).  
Inspired by the need for a simple, all-in-one desktop networking tool.  
