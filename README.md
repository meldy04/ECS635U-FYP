# AI-Assisted Attack Path Prioritisation for Airport IT Assets
Final Year Project - BSc Computer Science, Queen Mary University of London (2025/26)

## PROJECT AIMS
This project implements and evaluates an AI-assisted system that combines attack graph modelling with multi-objective genetic algorithm optimisation to prioritise attack paths within a simulated airport IT environment. The system is evaluated against manual penetration testing and CVSS-based ranking baselines.

## PREREQUISITES
- Docker and Docker Compose
- Python 3.10+
- Kali Linux VM with standard tooling (Nmap, Burp Suite, sqlmap, etc)

## Running the Simulated Environment
From the `airport-sim/` directory:

```bash
docker compose up -d --build
```

This brings up four interconnected vulnerable systems on a shared Docker network:

| System  | Host Port | Description                           |
|---------|-----------|---------------------------------------|
| Booking | 5002      | Internet-facing passenger reservations|
| DCS     | 8080      | Central hub: check-in, manifests, JWT |
| FIDS    | 5001      | Flight information display            |
| BHS     | 5003      | Baggage handling API                  |
| Redis   | 6379      | Pub/sub message broker                |
| DCS DB  | 5432      | PostgreSQL (DCS)                      |
| BHS DB  | 5433      | PostgreSQL (BHS)                      |

To tear down and reset between trials:

```bash
docker compose down && docker compose up -d --build
```

## Running the Attack Graph Generator and GA Optimiser
From the project root:
```bash
pip install -r requirements.txt
cd prioritisation
python attack_graph_generator.py
python ga_optimiser.py
```

## Reproducing the Experimental Results
Trial evidence and plotting scripts for the comparative figures can be found in `evaluation-data/`.

For trial evidence per trial:
```bash
cd evaluation-data/evidence
```
For plotting scripts:
```bash
cd evaluation-data
python assets_over_time.py
python critical_asset_coverage.py
python time_to_first_compromise.py
```

## Reproducing the Baseline Comparisons
The plotting script for the baseline charts can be found in `baselines/`:
```bash
cd baselines
python baselines.py
```

## Security Notice
This repository contains **intentionally vulnerable** software for academic research purposes. The systems much only be deployed on isolated networks and must not be exposed to the public internet.
