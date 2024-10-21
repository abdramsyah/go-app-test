# Go Task Management Application

A simple Task Management application built using Go, PostgreSQL, and MongoDB. This application demonstrates basic CRUD operations and handles tasks efficiently across both relational and non-relational databases.

## Table of Contents
- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [PostgreSQL](#postgresql)
  - [MongoDB](#mongodb)
- [VPS](#vps)
- [Running the Application](#running-the-application)

## Getting Started

Follow these instructions to get the project up and running on your local machine for development and testing purposes.

## Prerequisites

Ensure you have the following tools installed on your machine:
- Go (v1.22 or later)
- Docker (for running PostgreSQL, Redis and MongoDB easily)
- Git

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/abdramsyah/go-app-test.git
   cd go-app-test
2. ```
    go mod tidy

## **Configuration**
1. ```
    # PostgreSQL Configuration
    DB_HOST="210.79.191.14"
    DB_USERNAME="postgres"
    DB_PASSWORD="postgres"
    DB_PORT=5432
    DB_NAME="task_management"
    DB_MAX_POOL_SIZE=5  
    DB_BATCH_SIZE=1000

    # MongoDB Configuration
    MONGO_DB_HOST="210.79.191.14"
    MONGO_DB_USERNAME="root"
    MONGO_DB_PASSWORD="examplepassword"
    MONGO_DB_PORT=27017
    MONGO_DB_NAME="task_management"


## **running-the-application**
1. ```
    210.79.191.14
    username : test-go-app
    password : Testgoapp123

## **running-the-application**
1. ```
    air -c .air.toml