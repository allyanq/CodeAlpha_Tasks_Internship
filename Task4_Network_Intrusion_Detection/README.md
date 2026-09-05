# Task 4 — Network Intrusion Detection System

## Overview
A network-based Intrusion Detection System (IDS) built using Suricata for the CodeAlpha Cyber Security Internship.

## Features
- Monitors network traffic on eth0
- Detects ICMP traffic using a custom Suricata rule
- Generates alerts for detected traffic
- Stores alerts in Suricata log files

## Tools
- Kali Linux
- Suricata 8.0.6
- Custom Suricata rules

## Detection Rule
The custom rule detects ICMP traffic and generates:

CODEALPHA ICMP TEST ALERT

## Testing
Safe ICMP test traffic was generated using ping and verified through Suricata's alert log.

## Ethical Use
This project was created for authorized cybersecurity education and testing only.
