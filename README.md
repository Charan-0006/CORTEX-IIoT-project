# CORTEX-IIoT

## Context & Graph-Aware Multi-Agent Framework for Explainable Industrial IoT Threat Intelligence

CORTEX is a context and graph-aware multi-agent framework designed for detecting, investigating, and explaining security threats in Industrial Internet of Things (IIoT) environments.

The framework integrates **Context Intelligence**, **Adaptive Graph Intelligence**, and **Multi-Agent AI reasoning** to transform heterogeneous IIoT security telemetry into structured and explainable threat intelligence.

---

# 📌 Overview

Industrial IoT environments generate large volumes of heterogeneous network and operational data. Traditional security analysis often treats individual events independently, making it difficult to understand the relationships between entities, activities, and attack stages.

CORTEX addresses this challenge by combining:

- Context-aware analysis
- Temporal graph representations
- Network provenance analysis
- Multi-agent AI reasoning
- Confidence-based intelligence fusion
- Explainable incident reporting

The goal is to provide security analysts with a more contextual understanding of **what happened, how the attack progressed, which entities were involved, and why the activity is considered suspicious**.

---

# 🎯 Objectives

- Analyze heterogeneous IIoT network and security telemetry.
- Build dynamic operational context from observed activities.
- Model relationships between hosts, services, alerts, and security events.
- Reconstruct potential attack paths using temporal relationships.
- Identify important and suspicious entities using graph analytics.
- Combine contextual and graph intelligence using multiple AI agents.
- Generate structured and explainable threat intelligence.
- Support incident investigation and response through a dashboard.

---

# 🏗️ System Architecture

```text
                    IIoT Security Datasets
                              │
                              ▼
              ┌────────────────────────────┐
              │ Data Ingestion &            │
              │ Preprocessing               │
              └─────────────┬──────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
┌──────────────────────────┐   ┌──────────────────────────┐
│ Context Intelligence     │   │ Adaptive Graph           │
│ Engine                   │   │ Intelligence Engine      │
│                          │   │                          │
│ • Context Acquisition    │   │ • Temporal Knowledge     │
│ • Context Profiles       │   │   Graph                  │
│ • Operational Context    │   │ • Network Provenance     │
│ • Contextual Reasoning   │   │   Graph                  │
│ • Context Confidence     │   │ • Graph Refinement       │
└─────────────┬────────────┘   │ • Attack Path Analysis   │
              │                │ • Graph Analytics        │
              │                └────────────┬─────────────┘
              │                             │
              └──────────────┬──────────────┘
                             ▼
                ┌─────────────────────────┐
                │     Multi-Agent AI      │
                │         Layer           │
                │                         │
                │ • Context Analysis      │
                │ • Graph Investigation   │
                │ • Threat Intelligence   │
                │ • Confidence Fusion     │
                │ • Incident Response     │
                │ • Report Generation     │
                └────────────┬────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ Explainable Threat      │
                │ Intelligence            │
                └────────────┬────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ Dashboard & Reports     │
                └─────────────────────────┘


```

---

## 📊 Datasets

The project works with publicly available IIoT and IoT security datasets.

### Datasets

- **ToN-IoT**

The current development and validation work primarily uses the **ToN-IoT Network Dataset**.

### ToN-IoT Network Dataset

The Network Provenance Graph development uses the ToN-IoT Network Dataset.

The network data contains fields such as:

| Field | Description |
|---|---|
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `proto` | Network protocol |
| `service` | Network service |
| `duration` | Flow duration |
| `label` | Normal or malicious label |
| `type` | Attack type |
| `ts` | Event timestamp |

These fields are used for network flow analysis, entity extraction, graph construction, temporal analysis, and threat intelligence generation.

> The complete datasets are not included in this repository because of their size. Dataset setup instructions are provided in `data/README.md`.

---

## 🧠 Core Components

### 1. Data Ingestion & Preprocessing

The data processing layer prepares heterogeneous IIoT telemetry for downstream analysis.

Main operations include:

- Data loading
- Data parsing
- Missing-value handling
- Duplicate removal
- Feature organization
- Normalization
- Timestamp processing
- Data preparation for context and graph analysis

---

### 2. Context Intelligence Engine

The Context Intelligence Engine builds an operational understanding of IIoT entities and their activities.

Key areas include:

- Context acquisition
- Dynamic context profiles
- Operational context modeling
- Contextual reasoning
- Context consistency analysis
- Context confidence estimation

The engine helps determine whether observed activities are consistent with the expected operational behavior of the environment.

---

### 3. Adaptive Graph Intelligence Engine

The Adaptive Graph Intelligence Engine represents IIoT security information using graph-based structures.

Key capabilities include:

- Temporal Knowledge Graph construction
- Network Provenance Graph construction
- Graph refinement
- Graph validation
- Attack path reconstruction
- Graph relationship analysis
- Graph analytics

The graph layer preserves relationships between network entities and security events that may be lost when events are analyzed independently.

---

### 4. Multi-Agent AI Layer

The Multi-Agent AI layer uses specialized agents to collaboratively analyze contextual and graph intelligence.

The planned agent roles include:

- Context Analysis Agent
- Graph Investigation Agent
- Threat Intelligence Agent
- Confidence Fusion Agent
- Incident Response Agent
- Report Generation Agent

These agents divide the investigation process into specialized reasoning tasks and contribute to explainable threat analysis.

---

### 5. Threat Intelligence & Confidence Fusion

The threat intelligence layer combines information generated by the Context Intelligence and Graph Intelligence components.

The generated intelligence can include:

- Source entity
- Target entity
- Attack type
- Network service
- Attack path
- Important entities
- Contextual indicators
- Graph indicators
- Supporting evidence

Confidence information from different intelligence sources can be used during Multi-Agent reasoning to improve the reliability of threat assessment.

---

### 6. Dashboard & Explainable Intelligence

The dashboard provides a visual interface for presenting the generated security intelligence.

The final system is intended to display:

- Threat Score
- Confidence
- Attack Timeline
- Attack Graph
- Risk Indicators
- Important Entities
- Recommendations
- Explainable Incident Reports

---

## 📁 Project Structure

```text
CORTEX-IIoT/
│
├── data/
│   ├── README.md
│   └── sample/
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
```




## 👥 Team

### CORTEX-IIoT – Final Year Project

| Team Member | Contribution |
|---|---|
| **Lokpradeep B** | Adaptive Graph Intelligence --> src/graph_engine/TKG |
| **Uday Ganesh B** | Context Intelligence & System Integration |
| **Sri Charan N** | Network Provenance Graph & Multi-Agent Integration --> src/graph_engine/network_provenance_graph<br>|
| **Akshara Kruti P** | Contextual Reasoning & Confidence |

### Project Guide

**Dr. Kurunandan Jain**  



## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
