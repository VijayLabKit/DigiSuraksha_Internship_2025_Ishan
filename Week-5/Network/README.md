Perfect 👍 Here’s the **ready-to-paste README.md** in a short, point-to-point format:

````markdown
# Mini Network IPS

A simple Python-based Intrusion Prevention System (IPS) for detecting floods, scans, and malicious payloads.  
Works with **PCAP files** (offline) or **live network sniffing**.

---

## 📦 Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/yourname/mini-ips.git
   cd mini-ips
````

2. Install dependencies:

   ```bash
   pip install scapy pytest
   ```

---

## 🚀 Usage

* **Analyze a PCAP file**

  ```bash
  python main.py --pcap samples/traffic.pcap
  ```

* **Live sniffing (requires root)**

  ```bash
  sudo python main.py --live eth0
  ```

* **Print allowed traffic too**

  ```bash
  python main.py --pcap samples/traffic.pcap --print-allowed
  ```

* **Custom thresholds**

  ```bash
  python main.py --pcap attack.pcap --icmp-rate 50 --syn-rate 100 --scan-ports 10
  ```

---

## 🧪 Run Tests

```bash
pytest -v
```

---

## ⚠️ Note

For **educational/demo use only** – not production-ready.

```

Want me to also generate a **`requirements.txt`** snippet (so you can include it in your repo) alongside this README?
```
