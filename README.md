# Data Loss Prevention (DLP) System

## Thesis Project for Pontificia Universidad Católica del Perú

### Authors

[Oliver Bustamante]
[Angel Bravo]

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Project Overview](#project-overview)
4. [Features](#features)
5. [Architecture](#architecture)
6. [Configuration](#configuration)
7. [Database Schema](#database-schema)

## Introduction

This Data Loss Prevention (DLP) system is a comprehensive solution designed to protect sensitive information from unauthorized access, leakage, or misuse. Developed as a thesis project at Pontificia Universidad Católica del Perú, this system combines advanced pattern recognition, customizable rules, and real-time monitoring to safeguard data across various communication channels and file types.

## Installation

This project requires Python 3.12 and uses uv as project manager. Before running the project make you count with uv already installed, if not check the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).
To install the project, run the following command:

```bash
uv sync
```

Once that done ensure all other parts of the project (proxy, database, and api) are running.
For starting a simple DLP server, you can use the provided setup running the following command:

```bash
uv run setup.py
```

## Project Overview

The DLP system is built using Python and leverages several key technologies:

-   **Presidio**: For analyzing and anonymizing sensitive data
-   **PyICAP**: For intercepting and modifying network traffic
-   **PostgreSQL**: For storing configuration, rules, and logs
-   **pdfminer** and **python-docx**: For parsing PDF and DOCX files

The system is designed to be flexible, scalable, and easily integrated into existing network infrastructures.

## Features

-   Real-time content analysis of network traffic
-   Custom entity recognition for region-specific data types (e.g., DNI for Peru)
-   Support for multiple file types including plain text, PDF, and DOCX
-   Configurable rules with different action levels (Alert, Redact, Block)
-   User management with role-based access control
-   Detailed logging and auditing of DLP events
-   Network segmentation support for targeted rule application

## Architecture

The system consists of several key components:

1. **ICAP Server**: Intercepts and processes network traffic
2. **DLP Core**: Analyzes content using Presidio and custom rules
3. **File Handlers**: Parse and modify various file types
4. **Database**: Stores configuration, rules, and logs
5. **API** (not shown in the provided code, but recommended): For configuration and reporting

## Configuration

The system can be configured through the PostgreSQL database. Key configuration areas include:

-   Custom Entity Types
-   Detection Patterns
-   DLP Rules
-   Network Segments
-   User Roles and Permissions

## Database Schema

The PostgreSQL database includes the following key tables:

-   `custom_entity_types`: Defines custom data types to detect
-   `custom_patterns`: Regular expressions for detecting custom entities
-   `rules`: DLP rules defining actions and thresholds
-   `networks`: Network segments for targeted rule application
-   `users` and `roles`: User management and access control
-   `history`: Logs of DLP events

