# Troubleshooting

## Keycloak: token non valido
- assicurati di aver eseguito `./scripts/init_keycloak.sh`
- verifica realm e client su http://localhost:8080 (admin/admin)

## MinIO: bucket mancante
- esegui `./scripts/init_minio.sh`
- controlla console: http://localhost:9001

## Postgres: permission denied
- esegui `./scripts/init_db.sh`
- verifica che `.env` punti a `localhost:5432`

## OpenClaw non raggiungibile
- i test che dipendono da OpenClaw vengono skippati
- verifica `OPENCLAW_HTTP_BASE` e che OpenClaw sia attivo sull’host
