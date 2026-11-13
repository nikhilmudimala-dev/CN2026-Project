# Dynamic Host Blocking System Using Software-Defined Networking (SDN)

## Project Overview

This project implements a Dynamic Host Blocking System using Software-Defined Networking (SDN).

The system monitors TCP traffic, identifies suspicious network behaviour and dynamically blocks hosts responsible for abnormal traffic patterns.

The SDN controller acts as the central decision-making component, communicating with network switches to enforce blocking rules.

## Objectives

- Monitor TCP traffic in an SDN-based network.
- Detect abnormal TCP SYN activity.
- Detect unusually high numbers of completed TCP connections.
- Identify TCP port scanning behaviour.
- Dynamically block suspicious hosts.
- Classify detected activity based on severity.
- Maintain detection and blocking event records.

## Detection Rules

| Rule | Detection | Response |
|---|---|---|
| R1 | TCP SYN Burst | Temporary blocking |
| R2 | TCP Connection Burst | Temporary blocking |
| R3 | TCP Port Scan | Alert generation |

## System Architecture

The project consists of the following major components:

- **Mininet Topology:** Creates the network with switches and hosts.
- **SDN Controller:** Monitors network traffic and coordinates responses.
- **Packet Collector:** Extracts relevant information from packets.
- **Detection Engine:** Coordinates the detection rules.
- **Detection Pipeline:** Processes detection results and coordinates responses.
- **Blocking Manager:** Installs and manages blocking rules.
- **Database:** Stores detection and blocking events.
- **Dashboard:** Provides an interface to launch traffic scenarios and observe system activity.

## Traffic Scenarios

The dashboard supports five predefined scenarios:

1. Normal Traffic
2. TCP SYN Burst
3. TCP Connection Burst
4. TCP Port Scan
5. Mixed Traffic

## Technologies Used

- Python
- Mininet
- Open vSwitch
- OS-Ken SDN Controller
- OpenFlow 1.3
- Flask
- SQLite

## Project Structure

The repository contains the network topology, controller, detection modules, traffic generation system, database, dashboard, configuration files and supporting documentation.

## Running the Project

### 1. Start the SDN Controller

```bash
source ~/sdn-host-blocking/.venv/bin/activate
osken-manager sdn_controller.py
```

### 2. Start the Mininet Network

```bash
sudo mn -c
sudo python3 network/topology.py
```

### 3. Start the Dashboard

```bash
source ~/sdn-host-blocking/.venv/bin/activate
python3 -m dashboard.app
```

Open the dashboard at:

`http://127.0.0.1:5000`

## Team Contributions

### 1. Nikhil Reddy Mudimala
- Designed and implemented the SDN controller.
- Developed the detection engine and detection pipeline.
- Implemented TCP SYN burst detection and TCP connection burst detection.
- Implemented TCP port scan detection.
- Developed the traffic generation system and predefined traffic scenarios.
- Implemented the dashboard and traffic control interface.
- Integrated the system components and handled overall project integration and testing.

### 2. Parimala
- Developed the database module.
- Implemented database schema and data management.
- Developed the event manager for recording and managing system events.

### 3. Karthik Kumar
- Developed the Mininet network topology.
- Implemented the severity classification module.
- Developed the blocking manager for managing host blocking operations.

## Demonstration

Screenshots and demonstration recordings can be added to the repository as supporting material.
