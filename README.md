# SysAudit AI

> **An AI-powered Windows system auditor that explains your computer like an expert engineer.**

SysAudit AI collects a comprehensive snapshot of a Windows system and allows an AI assistant to analyze, explain, and answer questions about the machine in plain English.

Instead of showing thousands of processes, registry entries, services, and network connections, SysAudit AI helps users understand **why** their system behaves the way it does.

---

# Vision

Modern diagnostic tools expose raw data.

SysAudit AI turns that data into actionable knowledge.

Examples:

* Why is my PC slow?
* What is using all my RAM?
* Is this process safe?
* What starts when Windows boots?
* Why is this port open?
* Is anything suspicious?
* What changed since last week?
* Can I safely disable this service?

The goal is to provide an experience similar to chatting with an experienced Windows systems engineer.

---

# Features

## System Snapshot

Collect a comprehensive snapshot of the current system, including:

* Operating System
* Hardware Information
* CPU
* Memory
* Storage
* Running Processes
* Windows Services
* Startup Programs
* Network Connections
* Installed Software
* Drivers
* Scheduled Tasks
* Windows Security
* Event Logs
* Browser Extensions (planned)
* Docker & WSL (planned)

---

## AI Analysis

Generate intelligent explanations such as:

* Performance bottlenecks
* Startup impact
* Memory usage
* CPU hotspots
* Network activity
* Suspicious processes
* Service recommendations
* Security observations
* System health overview

---

## Interactive Chat

Ask questions naturally.

Example:

```
Why is my PC slow?

What is using all my RAM?

Can I disable Lenovo Service Bridge?

Is this process malware?

Why is port 8080 open?

Why do I have so many svchost.exe processes?
```

---

# Project Goals

* Zero installation experience
* One-command execution
* Complete system snapshot
* Human-readable explanations
* AI-first architecture
* Modular collectors
* Privacy-first design

---

# Architecture

```
Windows System
        │
        ▼
System Collectors
        │
        ▼
Structured JSON Report
        │
        ▼
AI Analysis Engine
        │
        ▼
Interactive Chat Interface
```

---

# Planned Collector Modules

```
collectors/

system.py
hardware.py
cpu.py
memory.py
storage.py
processes.py
services.py
startup.py
network.py
drivers.py
tasks.py
software.py
security.py
eventlogs.py
browser.py
docker.py
wsl.py
```

Each collector is responsible for gathering one specific category of information and returning structured data.

---

# Project Structure

```
SysAudit-AI/

collectors/
backend/
frontend/
schemas/
docs/
tests/

README.md
requirements.txt
```

---

# Roadmap

## Phase 1

* [ ] System information
* [ ] CPU
* [ ] Memory
* [ ] Disk
* [ ] Processes
* [ ] Services
* [ ] Startup programs
* [ ] Network connections
* [ ] JSON report generation

## Phase 2

* [ ] Installed applications
* [ ] Drivers
* [ ] Scheduled tasks
* [ ] Windows Defender
* [ ] Firewall
* [ ] Event logs
* [ ] Hardware details

## Phase 3

* [ ] AI backend
* [ ] Interactive chat
* [ ] Automatic report upload
* [ ] Browser interface

## Phase 4

* [ ] Historical snapshots
* [ ] Change detection
* [ ] AI recommendations
* [ ] One-click safe fixes

---

# Tech Stack

## Collector

* Python

## AI

* OpenAI Responses API (initial)
* Additional LLM providers planned

## Frontend

* HTML
* JavaScript

## Backend

* FastAPI

---

# Guiding Principles

* Never guess when system data can be collected.
* Prefer native Windows APIs over fragile parsing.
* Explain technical concepts in plain language.
* Keep collectors modular and independently testable.
* Separate data collection from AI reasoning.
* Prioritize transparency and user privacy.

---

# Current Status

🚧 Early development

The current focus is building reliable system collectors and defining a stable report schema that will power future AI analysis.
