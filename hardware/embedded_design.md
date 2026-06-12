# Embedded Deployment Design

## Objective

Deploy ARGUS as a lightweight embedded cybersecurity device capable of operating continuously within local networks.

---

# Proposed Architecture

Network
↓
ARGUS Device
↓
Router
↓
Internet

The device monitors traffic passing through the network and performs local threat analysis.

---

# Candidate Hardware

## Raspberry Pi 5

Advantages:

* Sufficient processing capability
* Low power consumption
* Community support

---

## NVIDIA Jetson Nano

Advantages:

* Hardware acceleration
* AI-focused architecture
* Edge inference support

---

## Custom Embedded Board

Long-term objective for commercial deployment.

---

# Core Embedded Modules

## Traffic Collection Module

Captures network traffic.

## Feature Extraction Module

Processes packet data.

## ML Inference Engine

Executes trained detection models.

## Response Engine

Initiates blocking and mitigation.

## Monitoring Interface

Provides user visibility.

---

# Expected Benefits

* Portable deployment
* Low operating cost
* Continuous protection
* Local processing
* Reduced cloud dependency
