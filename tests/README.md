# Tests (stato attuale)

La suite in `tests/` copre endpoint BFF e una parte della surface OpenAI-compatible con approccio smoke/integration leggero.

Sono presenti anche test unitari locali per logica endpoint agenti (`tests/test_agents.py`) eseguibili senza backend in ascolto.

## Prerequisiti

- Backend avviato su `BASE_URL` (default `http://localhost:8000`)
- Infra pronta (`./scripts/init_all.sh`)
- OpenClaw raggiungibile per i test che lo richiedono

## Auth nelle fixture

- `KEYCLOAK_ENABLED=false`: header `X-Debug-User`
- `KEYCLOAK_ENABLED=true`: token ottenuto via password grant da Keycloak (`tests/conftest.py`)

## Note importanti

- Alcuni test sono **legacy** rispetto al contratto API attuale (naming/shape risposte).
- `tests/test_openai_proxy.py` contiene una aspettativa legacy di conversation alias routing (`/v1/responses`) non più rappresentativa del comportamento attuale.
- I test OpenClaw-dependent in alcuni casi sono marcati con skip esplicito.
- Interpreta la suite come baseline di regressione, non come copertura completa end-to-end.
