# CORTEX-IIoT

## Context & Graph-Aware Multi-Agent Framework for Explainable Industrial IoT Threat Intelligence

CORTEX is a context and graph-aware multi-agent framework designed for detecting, investigating, and explaining security threats in Industrial Internet of Things (IIoT) environments.

The framework integrates contextual intelligence, graph-based threat analysis, and Multi-Agent AI reasoning to provide explainable and structured threat intelligence from heterogeneous IIoT security data.

---

## 🎯 Objectives

- Analyze heterogeneous IIoT network and security telemetry.
- Build dynamic operational context from observed activities.
- Model relationships between hosts, services, alerts, and security events.
- Reconstruct and analyze potential attack paths.
- Identify important and suspicious entities using graph analytics.
- Combine contextual and graph intelligence using multiple AI agents.
- Generate explainable threat intelligence, risk indicators, and incident reports.

---

## 🏗️ System Architecture

```text
IIoT Security Datasets
          │
          ▼
┌──────────────────────────────┐
│ Data Ingestion & Preprocessing│
└──────────────────────────────┘
          │
          ▼
┌──────────────────────────────┐
│ Context Intelligence Engine  │
│                              │
│ • Context Acquisition        │
│ • Dynamic Context Profiles   │
│ • Operational Context       │
│ • Contextual Reasoning       │
│ • Context Confidence         │
└──────────────────────────────┘
          │
          ▼
┌──────────────────────────────┐
│ Adaptive Graph Intelligence  │
│            Engine             │
│                              │
│ • Temporal Knowledge Graph   │
│ • Network Provenance Graph   │
│ • Graph Refinement           │
│ • Attack Path Analysis       │
│ • Graph Analytics            │
└──────────────────────────────┘
          │
          ▼
┌──────────────────────────────┐
│       Multi-Agent AI         │
│                              │
│ • Context Analysis           │
│ • Graph Investigation        │
│ • Threat Intelligence        │
│ • Confidence Fusion         │
│ • Incident Response          │
│ • Report Generation          │
└──────────────────────────────┘
          │
          ▼
┌──────────────────────────────┐
│ Dashboard & Explainable      │
│ Threat Intelligence Reports  │
└──────────────────────────────┘


📊 Datasets

The project works with publicly available IIoT and IoT security datasets, including:

ToN-IoT

The current development and validation work primarily uses the ToN-IoT Network Dataset.

Complete datasets are not included in this repository because of their size. Dataset setup instructions are provided in data/README.md.

🧠 Core Components
1. Data Ingestion & Preprocessing

Handles the collection, cleaning, normalization, feature organization, and preparation of IIoT security data for downstream analysis.

2. Context Intelligence Engine

Builds an operational understanding of IIoT entities and their activities.

Key areas include:

Context acquisition
Dynamic context profiles
Operational context modeling
Contextual reasoning
Context consistency analysis
Context confidence estimation


3. Adaptive Graph Intelligence Engine

Represents IIoT security information as interconnected graph structures.

Key capabilities include:

Temporal Knowledge Graph construction
Network Provenance Graph construction
Graph refinement and validation
Attack path reconstruction
Graph-based relationship analysis
Graph centrality analytics


4. Multi-Agent AI Layer

Uses specialized AI agents to collaboratively analyze contextual and graph intelligence.

Agent roles include:

Context Analysis Agent
Graph Investigation Agent
Threat Intelligence Agent
Confidence Fusion Agent
Incident Response Agent
Report Generation Agent


5. Dashboard & Explainable Intelligence

Provides a user-facing view of the generated security intelligence, including:

Threat Score
Confidence
Attack Timeline
Attack Graph
Risk Indicators
Recommendations
Explainable Incident Reports


🔄 Overall Workflow
IIoT Data
   ↓
Data Preprocessing
   ↓
Context Intelligence
   +
Graph Intelligence
   ↓
Multi-Agent AI Reasoning
   ↓
Confidence & Threat Assessment
   ↓
Incident Analysis
   ↓
Explainable Report
   ↓
Dashboard


🛠️ Technologies
Python
Pandas
NumPy
NetworkX
Neo4j
CrewAI
Llama 3
Ollama
Matplotlib
PyTest


📁 Project Structure
CORTEX-IIoT/
│
├── data/
│
├── src/
│   ├── context_engine/
│   ├── graph_engine/
│   ├── agents/
│   ├── intelligence/
│   ├── dashboard/
│   └── workflow/
│
├── tests/
├── outputs/
├── docs/
├── notebooks/
│
├── README.md
├── requirements.txt
├── LICENSE
└── .gitignore


📌 Project Status
Completed
IIoT data ingestion and preprocessing
Context intelligence development
Graph intelligence development
Network Provenance Graph construction
Graph refinement and validation
Attack path analysis
Graph analytics
Structured intelligence generation
Initial Multi-Agent AI development
Visualization and testing

In Progress
Context and graph intelligence integration
Multi-Agent reasoning integration
Confidence and threat assessment
End-to-end system integration
Dashboard integration
Future Work
Advanced risk scoring
Multi-Agent confidence verification
Complete end-to-end deployment
Further performance evaluation

👥 Team
CORTEX-IIoT – Final Year Project
Lokpradeep B – Adaptive Graph Intelligence
Uday Ganesh B – Context Intelligence & System Integration
Sri Charan N – Network Provenance Graph & Multi-Agent Integration
Akshara Kruti P – Contextual Reasoning & Confidence

Project Guide:
Dr. Kurunandan Jain


📄 Documentation

Project architecture, methodology, implementation details, experimental results, and supporting documentation are available in the docs/ directory.

⚠️ Note

This project is developed for academic and research purposes as part of a final-year project focused on explainable Industrial IoT threat intelligence.
