# Data Loss Prevention (DLP) System

## Thesis Project for Pontificia Universidad Católica del Perú

### Authors
[Oliver Bustamante]
[Angel Bravo]

## Table of Contents
1. [Introduction](#introduction)
2. [Project Overview](#project-overview)
3. [Features](#features)
4. [Architecture](#architecture)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Configuration](#configuration)
8. [Database Schema](#database-schema)
9. [Contributing](#contributing)
10. [License](#license)
11. [Acknowledgements](#acknowledgements)

## Introduction

This Data Loss Prevention (DLP) system is a comprehensive solution designed to protect sensitive information from unauthorized access, leakage, or misuse. Developed as a thesis project at Pontificia Universidad Católica del Perú, this system combines advanced pattern recognition, customizable rules, and real-time monitoring to safeguard data across various communication channels and file types.

## Project Overview

The DLP system is built using Python and leverages several key technologies:

- **Presidio**: For analyzing and anonymizing sensitive data
- **PyICAP**: For intercepting and modifying network traffic
- **PostgreSQL**: For storing configuration, rules, and logs
- **pdfminer** and **python-docx**: For parsing PDF and DOCX files

The system is designed to be flexible, scalable, and easily integrated into existing network infrastructures.

## Features

- Real-time content analysis of network traffic
- Custom entity recognition for region-specific data types (e.g., DNI for Peru)
- Support for multiple file types including plain text, PDF, and DOCX
- Configurable rules with different action levels (Alert, Redact, Block)
- User management with role-based access control
- Detailed logging and auditing of DLP events
- Network segmentation support for targeted rule application

## Architecture

The system consists of several key components:

1. **ICAP Server**: Intercepts and processes network traffic
2. **DLP Core**: Analyzes content using Presidio and custom rules
3. **File Handlers**: Parse and modify various file types
4. **Database**: Stores configuration, rules, and logs
5. **API** (not shown in the provided code, but recommended): For configuration and reporting

## Installation

[Provide step-by-step installation instructions here, including dependencies]

## Usage

[Provide instructions on how to start and use the system, including any command-line arguments or configuration files]

## Configuration

The system can be configured through the PostgreSQL database. Key configuration areas include:

- Custom Entity Types
- Detection Patterns
- DLP Rules
- Network Segments
- User Roles and Permissions

[Provide more detailed instructions on how to configure each aspect]

## Database Schema

The PostgreSQL database includes the following key tables:

- `custom_entity_types`: Defines custom data types to detect
- `custom_patterns`: Regular expressions for detecting custom entities
- `rules`: DLP rules defining actions and thresholds
- `networks`: Network segments for targeted rule application
- `users` and `roles`: User management and access control
- `history`: Logs of DLP events

[You may want to include an ER diagram or more detailed schema description]

## Contributing

[If applicable, provide guidelines for how others can contribute to the project]

## License

[Specify the license under which this project is released]

## Acknowledgements

- Pontificia Universidad Católica del Perú for supporting this research
- [List any other individuals, organizations, or resources that contributed to the project]

---

For more information, please contact [Your Contact Information].

© [Year] [Your Name/Institution]. All Rights Reserved.
