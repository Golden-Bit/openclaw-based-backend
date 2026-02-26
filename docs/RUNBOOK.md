# Runbook – Avvio Infra + Backend

## 1) Avvio infra (Docker)
Dalla root del repo:

```bash
./scripts/start_infra.sh
```

## 2) Inizializzazione (DB + MinIO + Keycloak)
```bash
./scripts/init_all.sh
```

Questo crea:
- Postgres: db `openclaw_bff` + user `openclaw_bff`
- MinIO: bucket `openclaw-bff` + user `openclaw-bff`
- Keycloak: realm `openclaw-bff`, client `openclaw-bff-api`, utente `testuser`

## 3) Avvio backend su host
Copia `.env.example` → `.env`, poi:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./scripts/dev_run.sh
```

Swagger:
- http://localhost:8000/docs

## 4) Test
```bash
./scripts/run_tests.sh
```

> Nota: i test che dipendono da OpenClaw vengono skippati se OpenClaw non è raggiungibile.
