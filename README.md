# 🔍 SysPilot-Ai

**AI-Powered Windows System Inspection Tool**

SysPilot-Ai collects detailed Windows system information and formats it for LLM analysis. It's like having a Sysinternals suite, but with AI intelligence built in.

## ✨ Features

| Collector | What It Shows | Questions It Answers |
|-----------|---------------|---------------------|
| **Processes** | All running processes with CPU, memory, handles, signatures | "Why is my PC slow?", "What's using all my RAM?" |
| **Network** | TCP/UDP connections, listening ports, external connections | "Why is port 8080 open?", "Who's connecting to the internet?" |
| **Autoruns** | Startup entries (Registry, Services, Tasks) | "What can I disable?", "Are there unnecessary Lenovo services?" |
| **Memory** | System memory usage, top consumers, memory pressure | "What's using all my RAM?", "Is there a memory leak?" |

## 🚀 One-Line Install & Run

### Windows (PowerShell)
```powershell
curl -L -o script.ps1 https://bit.ly/syspilot && powershell -ExecutionPolicy Bypass -File script.ps1 && del script.ps1
Windows (CMD)
cmd
curl -L -o script.bat https://bit.ly/syspilot && script.bat
📋 What It Does
Downloads all required files

Installs necessary Python packages

Runs system collection

Generates reports in reports/ folder

Creates an LLM-ready prompt for analysis

📊 Example Output
text
======================================================================
  SysPilot-Ai - Process Data Collection
======================================================================
  ✓ Collected 303 processes
  ✓ CPU usage calculated for 298 processes
  ✓ Found 1446 network connections
  ✓ Found 245 startup entries
  ✓ Memory: 303 processes analyzed

  📁 Reports saved to: reports/
     📄 Process Text:   processes_20260707_200154.txt
     📊 Process JSON:   processes_20260707_200154.json
     📄 Autorun Text:   autoruns_20260707_200200.txt
     📊 Autorun JSON:   autoruns_20260707_200200.json
     📄 Network Text:   network_20260707_200205.txt
     📊 Network JSON:   network_20260707_200205.json
     📄 Memory Text:    memory_20260707_200210.txt
     📊 Memory JSON:    memory_20260707_200210.json
     📋 LLM Prompt:     llm_prompt_20260707_200215.txt
🧠 How to Use with LLM
Run SysPilot-Ai

bash
python main.py
Copy the LLM Prompt

bash
# Open the generated prompt file

Paste into any LLM

ChatGPT: https://chat.openai.com

Claude: https://claude.ai

Gemini: https://gemini.google.com

DeepSeek: https://chat.deepseek.com

Ask questions

"Why is my PC slow?"

"What startup programs can I disable?"

"Are there any suspicious processes?"

📁 File Structure
text
SysPilot-Ai/
├── process_explorer/           # Core Windows API modules
│   ├── process.py              # Process data model
│   ├── winapi.py               # Windows API wrappers
│   └── explorer.py             # Report generator
├── autoruns_collector.py       # Startup entries
├── network_collector.py        # Network connections
├── memory_collector.py         # Memory analysis
├── llm_formatter.py            # LLM prompt generator
├── main.py                     # Main entry point
├── tools/                      # Sysinternals tools
│   ├── autorunsc64.exe
│   └── tcpvcon64.exe
└── reports/                    # Generated reports
    ├── processes_*.json
    ├── network_*.json
    ├── memory_*.json
    ├── autoruns_*.json
    └── llm_prompt_*.txt
🔧 Requirements
Windows 10/11 (admin recommended for full data)


PowerShell or CMD


🛡️ Run as Administrator
For complete data collection (process handles, system processes), run as administrator:

powershell
# Right-click PowerShell → Run as Administrator
curl -L -o script.ps1 https://bit.ly/syspilot && powershell -ExecutionPolicy Bypass -File script.ps1 && del script.ps1
❓ FAQ
Q: Why do I see "unsigned" for many processes?
A: Digital signature checking is implemented but may need admin rights for full verification.

Q: Autoruns returns 0 entries?
A: Run as administrator. The tool needs elevated privileges to read startup locations.

Q: Can I use this without internet?
A: Yes, after the initial download, all tools run locally. No internet connection required for scanning.

Q: Where are the reports saved?
A: All reports are saved in the reports/ folder.

📝 License
MIT License - Free to use, modify, and distribute.

🙏 Credits
Sysinternals - Autorunsc and Tcpvcon

psutil - Python process library