````markdown
# 🔍 SysPilot-AI

> **AI-powered Windows system inspection for LLMs**

SysPilot-AI collects detailed Windows diagnostics and formats them into reports that Large Language Models (LLMs) can analyze. Instead of manually inspecting Task Manager, Process Explorer, Autoruns, and network utilities, simply run SysPilot-AI and ask an AI questions about your computer.

---

## ✨ Features

| Collector | Information Collected | Questions It Can Answer |
|------------|----------------------|-------------------------|
| 🖥 **Processes** | Running processes, CPU usage, memory usage, handles, threads, digital signatures | Why is my PC slow? What is using all my RAM? |
| 🌐 **Network** | TCP/UDP connections, listening ports, remote endpoints | Why is port 8080 open? Which applications are using the internet? |
| 🚀 **Autoruns** | Startup applications, services, scheduled tasks | What starts with Windows? What can I safely disable? |
| 🧠 **Memory** | System memory usage, top consumers, memory pressure | Is there a memory leak? Do I need more RAM? |

---

# 🚀 Quick Start

## PowerShell (Recommended)

```powershell
curl -L -o script.ps1 https://bit.ly/syspilot && powershell -ExecutionPolicy Bypass -File script.ps1 && del script.ps1
```

## Command Prompt

```cmd
curl -L -o script.bat https://bit.ly/syspilot && script.bat
```

---

# 📦 What Happens

Running the installer automatically:

- Downloads SysPilot-AI
- Downloads required Sysinternals tools
- Installs required Python packages
- Collects Windows diagnostic information
- Generates human-readable reports
- Generates JSON reports
- Creates an AI-ready analysis prompt

Everything runs locally on your machine.

---

# 🤖 Analyze with AI

After the scan completes, open the generated **`reports`** folder.

You have **two ways** to analyze your computer.

## Option 1 (Recommended)

Open the generated **`llm_prompt_*.txt`** file and upload **all generated reports** to your favorite AI assistant.

Supported assistants include:

- ChatGPT
- Claude
- Gemini
- DeepSeek
- Grok
- Any LLM capable of reading files

The prompt is specifically designed to correlate every report into one complete system analysis.

---

## Option 2

Use the pre-configured ChatGPT conversation:

**https://chatgpt.com/share/6a4e1037-9d9c-83e8-a2f4-bd377d2b8df8**

Simply upload all generated reports when prompted.

---

### Example Questions

Ask things like:

- Why is my PC slow?
- Is my computer healthy overall?
- What is using all my RAM?
- Are there any memory leaks?
- Which startup programs should I disable?
- Which processes consume the most CPU?
- Are there suspicious processes?
- Are there suspicious network connections?
- What background applications can I remove?
- What upgrades would improve performance?
- Is my CPU or RAM the bottleneck?
- Are there any unnecessary services running?

---

# 📊 Example Output

```text
======================================================================
SysPilot-AI - Process Data Collection
======================================================================

✓ Collected 303 processes
✓ CPU usage calculated for 298 processes
✓ Found 1446 network connections
✓ Found 245 startup entries
✓ Memory analyzed for 303 processes

📁 Reports saved to reports/

   📄 processes_20260707_200154.txt
   📊 processes_20260707_200154.json
   📄 autoruns_20260707_200200.txt
   📊 autoruns_20260707_200200.json
   📄 network_20260707_200205.txt
   📊 network_20260707_200205.json
   📄 memory_20260707_200210.txt
   📊 memory_20260707_200210.json
   📋 llm_prompt_20260707_200215.txt
```

---

# 📂 Project Structure

```text
SysPilot-AI/
│
├── process_explorer/
│   ├── process.py
│   ├── explorer.py
│   └── winapi.py
│
├── autoruns_collector.py
├── network_collector.py
├── memory_collector.py
├── llm_formatter.py
├── main.py
│
├── tools/
│   ├── autorunsc64.exe
│   └── tcpvcon64.exe
│
└── reports/
    ├── processes_*.txt
    ├── processes_*.json
    ├── network_*.txt
    ├── network_*.json
    ├── memory_*.txt
    ├── memory_*.json
    ├── autoruns_*.txt
    ├── autoruns_*.json
    └── llm_prompt_*.txt
```

---

# 🔧 Requirements

- Windows 10 or Windows 11
- Python 3.10+
- PowerShell or Command Prompt
- Administrator privileges (recommended)

---

# 🔒 Administrator Mode

Running SysPilot-AI as **Administrator** provides:

- Complete process information
- Access to protected system processes
- More Autoruns entries
- Better digital signature verification
- More complete system diagnostics

Although optional, Administrator mode is recommended for the most accurate analysis.

---

# ❓ FAQ

### Why are some processes marked as unsigned?

Windows restricts digital signature verification for certain system processes unless running with elevated permissions.

---

### Why are there no Autoruns entries?

Run SysPilot-AI as Administrator.

---

### Does SysPilot-AI require internet?

Only for the initial download.

System inspection is performed entirely offline.

---

### Are my reports uploaded anywhere?

No.

SysPilot-AI never uploads your reports or collects telemetry.

You decide whether to share the generated reports with an AI assistant.

---

# 🛠 Built With

- Microsoft Sysinternals
- psutil
- Windows API
- Python

---

# 📄 License

MIT License

---

## ⭐ If you find SysPilot-AI useful, consider starring the repository!
````
