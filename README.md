# Threat Hunt Report 

* Azuki Import/Export - 梓貿易株式会社
* Analyst: Alexis Annor-Larbi
* Platform: Microsoft Defender for Endpoint (MDE)
* Tools: KQL, Defender Tables, Endpoint Telemetry
* Date: Januray 15, 2026

## Executive Summary
This threat hunt report presents the results of an exercise that requires locating and capturing a specified number of flags.

## Table of Contents
1. Incident Summary
2. Flag-by-Flag Breakdown
3. Conclusion and Lessons Learned

## Incident Summary
A couple of days after a file server breach on the affected system, the same attackers decided to strike back with more efficient and stronger techniques. This time, it appears that the CEO's administrative personal computer has been the one to be affected. We know that the attacks started on November 24 2025.

## Flag-by-Flag Breakdown with Queries

### FLAG 1: LATERAL MOVEMENT - Source System

Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.
KQL query:
DeviceLogonEvents
| where DeviceName contains "azuki"
|where AccountName contains "yuki"


<img width="1388" alt="CTF -Artifact-flag1" src="https://i.imgur.com/zaWh93n.png" />

Answer: 10.1.0.204


### FLAG 2: LATERAL MOVEMENT - Source System

Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.
KQL query:
DeviceLogonEvents
| where DeviceName contains "azuki"
|where AccountName contains "yuki"


<img width="1388" alt="CTF -Artifact-flag1" src="https://i.imgur.com/zaWh93n.png" />

Answer: 10.1.0.204
