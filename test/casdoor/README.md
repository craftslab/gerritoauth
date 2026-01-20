# Casdoor (docker-compose, all-in-one)

This folder provides a minimal docker-compose setup for running Casdoor using the **toy database** image `casbin/casdoor-all-in-one`, matching Casdoor docs “Option-1: Use the toy database”.

Reference: [Casdoor docs: Try with Docker (Option-1)](https://www.casdoor.org/docs/basic/try-with-docker#option-1-use-the-toy-database)

## Run

From this directory:

```bash
docker compose up
```

Then open `http://localhost:8000`.

## Default login

- **Account**: `built-in/admin`
- **Username**: `admin`
- **Password**: `123`

## Stop

```bash
docker compose down
```
