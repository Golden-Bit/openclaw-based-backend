# Environment Reference

Guida completa alle variabili presenti in `.env.example`, con appendice dedicata alle variabili runtime aggiuntive lette direttamente dal codice.

## Come usare questa reference

- `Valore in .env.example` = valore di esempio o valore iniziale suggerito nel file.
- Non sempre coincide con il **default runtime reale** letto dal codice: dove ci sono differenze, sono segnalate inline e nelle note finali.
- Usa questa pagina come guida per compilare `.env` in locale, staging e produzione.
- Quando un valore contiene credenziali o token, trattalo come **segreto** e non committarlo in chiaro.
- Questa reference distingue tre casi: variabili presenti in `.env.example`, alias/nomi legacy ancora citati nei docs, e variabili runtime aggiuntive non presenti nel file example ma comunque lette dal backend.

## 1) Backend FastAPI / Uvicorn

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `BFF_PORT` | `8000` | Porta TCP su cui Uvicorn espone il backend. | Cambiala se la porta è già occupata o se il reverse proxy punta a una porta diversa. |
| `BFF_PUBLIC_BASE_URL` | `http://localhost:8000` | Base URL pubblica assoluta del backend. Serve soprattutto per generare link completi ai file condivisi. | In staging/prod va impostata al dominio pubblico reale, per esempio `https://api.example.com`. |
| `BFF_LOG_LEVEL` | `info` | Livello di logging desiderato per il backend. | Tipicamente `debug` in sviluppo, `info` o `warning` in produzione. **Nota importante:** il runtime Pydantic legge oggi `LOG_LEVEL`, quindi questo nome va trattato come alias/documentazione legacy. |
| `BFF_ENV` | `local` | Etichetta ambiente leggibile da umani, usata per distinguere local/dev/prod. | Utile per log e chiarezza operativa. **Nota importante:** il runtime Pydantic legge oggi `APP_ENV`, quindi questo nome non è il knob runtime principale. |
| `BFF_CORS_ORIGINS` | `*` | Origini browser consentite per chiamare il backend. | In produzione è meglio usare una lista esplicita separata da virgole invece di `*`. **Nota importante:** il runtime Pydantic legge oggi `CORS_ALLOW_ORIGINS`. |

## 2) Autenticazione / Keycloak

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `KEYCLOAK_ENABLED` | `false` | Abilita o disabilita la validazione JWT tramite Keycloak. | Se `false`, il backend usa `X-Debug-User` o `DEV_USER_ID`. Se `true`, serve `Authorization: Bearer <token>`. |
| `KEYCLOAK_PUBLIC_URL` | `http://localhost:8080` | URL pubblico di Keycloak, cioè quello visto da browser/client e usato come base per issuer e login reali. | In produzione deve essere il dominio esterno effettivo, ad esempio `https://auth.example.com`. **Nota:** è soprattutto una variabile di bootstrap/infra/docs; il backend runtime valida i token tramite `KEYCLOAK_ISSUER`, `KEYCLOAK_JWKS_URL` e `KEYCLOAK_AUDIENCE`. |
| `KEYCLOAK_INTERNAL_URL` | `http://localhost:8080` | URL interno usato da script bootstrap e health checks lato host/backend. | In container o reti separate può differire dal public URL. **Nota:** serve soprattutto a script/test, non è il controllo principale della validazione JWT runtime. |
| `KEYCLOAK_BASE_URL` | `http://localhost:8080` | Variabile legacy/compatibilità per ambienti o script più vecchi. | Mantienila coerente con le altre URL Keycloak se hai tooling legacy. |
| `KEYCLOAK_REALM` | `openclaw-bff` | Nome del realm Keycloak usato dal backend e dagli script di bootstrap. | Cambialo se il realm reale ha un altro nome. |
| `KEYCLOAK_CLIENT_ID` | `openclaw-bff-api` | Client OIDC usato dal backend per validare token e dai flussi di test/bootstrap. | Deve restare coerente con il client creato in Keycloak. |
| `KEYCLOAK_ISSUER` | `http://localhost:8080/realms/openclaw-bff` | Issuer OIDC atteso nei JWT. | Deve corrispondere al realm e al dominio pubblico reali. |
| `KEYCLOAK_JWKS_URL` | `http://localhost:8080/realms/openclaw-bff/protocol/openid-connect/certs` | Endpoint JWKS da cui il backend recupera le chiavi pubbliche per validare i token. | Se è errato, l'autenticazione fallisce anche con token validi. |
| `KEYCLOAK_AUDIENCE` | `openclaw-bff-api` | Audience attesa nei token JWT. | Deve corrispondere al client configurato lato Keycloak. |
| `KC_HOSTNAME` | `http://localhost:8080` | Hostname/runtime setting di Keycloak usato soprattutto dietro proxy. | In produzione impostalo al dominio pubblico coerente con `KEYCLOAK_PUBLIC_URL`. |
| `KC_HTTP_ENABLED` | `true` | Controlla se Keycloak accetta traffico HTTP verso il container/processo. | Tipico `true` se la TLS è terminata dal proxy esterno. |
| `KC_PROXY_HEADERS` | `xforwarded` | Tipo di header proxy che Keycloak si aspetta (`xforwarded` o `forwarded`). | Va allineato a come il proxy inoltra `X-Forwarded-*` / `Forwarded`. |
| `KC_HOSTNAME_STRICT` | `false` | Rende più o meno rigido il controllo hostname di Keycloak. | In ambienti dietro proxy spesso resta `false` durante setup o migrazione. |
| `KEYCLOAK_ADMIN_USER` | `admin` | Username admin usato dagli script di bootstrap Keycloak. | È un segreto operativo: cambialo nei deploy reali. |
| `KEYCLOAK_ADMIN_PASSWORD` | `admin` | Password admin usata dagli script di bootstrap Keycloak. | È un segreto operativo: mai lasciare il valore di esempio in produzione. |
| `KEYCLOAK_TEST_USER` | `testuser` | Utente di test creato dagli script per i test automatici. | Utile in locale/CI; non è necessario in ambienti dove i test non usano password grant. |
| `KEYCLOAK_TEST_PASSWORD` | `testpassword` | Password dell'utente di test Keycloak. | Trattala come segreto se il test user esiste anche fuori dal locale. |
| `DEV_USER_ID` | `dev-user` | Identità utente usata quando `KEYCLOAK_ENABLED=false`. | Importante in sviluppo perché influenza namespace utente, ownership agenti e path di workspace. |

## 3) Database / Postgres

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `BFF_DB_HOST` | `localhost` | Host Postgres usato dagli script di bootstrap locale. | Cambialo se Postgres gira su altro host/container/network alias. |
| `BFF_DB_PORT` | `5432` | Porta Postgres usata dagli script. | Cambiala se il servizio DB non espone la porta standard. |
| `BFF_DB_NAME` | `openclaw_bff` | Nome del database applicativo. | Tienilo coerente con `DATABASE_URL` e con gli script `init_db.sh`. |
| `BFF_DB_USER` | `openclaw_bff` | Utente applicativo del database. | Da personalizzare in ambienti condivisi o più rigidi. |
| `BFF_DB_PASSWORD` | `openclaw_bff` | Password dell'utente applicativo del database. | È un segreto: va cambiata in staging/prod. |
| `DATABASE_URL` | `postgresql+asyncpg://openclaw_bff:openclaw_bff@localhost:5432/openclaw_bff` | DSN effettivo usato dal backend per connettersi al DB. | È la variabile più importante lato runtime DB. Se cambi host, porta, user o db, aggiorna anche questa. |
| `POSTGRES_SUPERUSER` | `postgres` | Superuser usato dagli script per creare DB e ruolo applicativi. | Serve soprattutto in bootstrap iniziale. |
| `POSTGRES_SUPERPASS` | `postgres` | Password del superuser Postgres usata dagli script. | È un segreto operativo. |
| `POSTGRES_SUPERDB` | `postgres` | DB iniziale a cui lo script si connette come superuser per creare ruolo e database applicativi. | Di solito resta `postgres`. |

## 4) MinIO

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `MINIO_ENDPOINT` | `localhost:9000` | Endpoint MinIO in formato `host:port` senza schema. | Non usare `http://` qui. Cambialo se MinIO non è locale. |
| `MINIO_SECURE` | `false` | Se `true`, il backend usa HTTPS verso MinIO. | Mettilo a `true` solo se MinIO è esposto in TLS. |
| `MINIO_BUCKET` | `openclaw-bff` | Bucket usato dal backend per upload e download object storage. | Deve esistere o essere creabile dal bootstrap. |
| `MINIO_CONSOLE` | `http://localhost:9001` | URL console web MinIO. | È informativo/operativo, utile per accesso manuale. |
| `MINIO_ROOT_USER` | `minioadmin` | Root user MinIO usato dagli script di inizializzazione. | Segreto operativo da cambiare in ambienti reali. |
| `MINIO_ROOT_PASSWORD` | `minioadmin` | Root password MinIO usata dagli script. | Segreto operativo da cambiare in ambienti reali. |
| `MINIO_BFF_ACCESS_KEY` | `openclaw-bff` | Credenziale applicativa prevista dagli script per l'utente MinIO dedicato al backend. | Deve restare coerente con l'utente creato da `init_minio.sh`. |
| `MINIO_BFF_SECRET_KEY` | `openclaw-bff-secret` | Secret applicativo previsto dagli script per l'utente MinIO del backend. | È un segreto e va cambiato nei deploy reali. |
| `MINIO_ACCESS_KEY` | `openclaw-bff` | Credenziale che il backend usa direttamente per autenticarsi a MinIO. | In pratica deve puntare allo stesso utente applicativo creato dagli script. |
| `MINIO_SECRET_KEY` | `openclaw-bff-secret` | Secret che il backend usa direttamente per autenticarsi a MinIO. | È un segreto e deve essere coerente con l'utente applicativo reale. |
| `MINIO_PRESIGN_EXPIRE_SECONDS` | `3600` | Scadenza suggerita per URL presigned nelle note del file example. | **Nota importante:** il runtime oggi usa `UPLOAD_PRESIGN_PUT_EXPIRES_SECONDS` e `UPLOAD_PRESIGN_GET_EXPIRES_SECONDS`, quindi questa variabile da sola non governa il comportamento reale del backend. |
| `MINIO_PUBLIC_BASE_URL` | `http://localhost:9000` | Base URL pubblica/esterna di MinIO se il backend deve costruire URL raggiungibili da client o altri servizi. | In produzione tipicamente punta a dominio o reverse proxy dedicato. |

## 5) OpenClaw

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `OPENCLAW_WS_DEBUG` | `1` | Abilita log diagnostici lato integrazione WebSocket OpenClaw. | Tienilo alto solo in locale o per troubleshooting mirato. |
| `OPENCLAW_WS_DEBUG_PAYLOAD` | `1` | Include anche i payload nei log debug WS. | Attenzione: può esporre dati sensibili nei log. |
| `OPENCLAW_WS_DEBUG_EVENTS` | `chat,agent` | Filtra i tipi di eventi WS da loggare. | Utile per ridurre rumore nei debug. |
| `OPENCLAW_HTTP_BASE` | `http://localhost:18789` | Base URL HTTP del gateway OpenClaw. | Il backend la usa per la surface compatibile OpenAI e chiamate HTTP correlate. |
| `OPENCLAW_WS_URL` | `ws://localhost:18789/ws` | URL WebSocket RPC del gateway OpenClaw. | Se è errata, agenti/chat/operazioni WS falliscono. |
| `OPENCLAW_BEARER_TOKEN` | `dce336a86dc9a3cb2833bc6aab78bcacba5f7281bac1b302` | Token bearer usato dal backend per parlare con OpenClaw quando il gateway richiede auth. | È un segreto: in produzione non va committato né lasciato di esempio. |
| `OPENCLAW_CLIENT_ID` | `gateway-client` | Identità client dichiarata dal backend verso OpenClaw. | Cambiala solo se il gateway o la policy richiedono un client id diverso. |
| `OPENCLAW_CLIENT_MODE` | `backend` | Modalità/ruolo client dichiarata verso OpenClaw. | Le alternative commentate in `.env.example` mostrano esempi come `tui` o `webchat`. |
| `OPENCLAW_ROLE` | `operator` | Role autorizzativo usato verso OpenClaw. | Deve essere coerente con i permessi attesi dal gateway. |
| `OPENCLAW_SCOPES` | `operator.read,operator.write,operator.admin` | Scope richiesti dal backend quando si presenta a OpenClaw. | Riducili o modificali solo se sai quali API userai davvero. |
| `OPENCLAW_IDENTITY_FILE` | `~/.openclaw/identity/device.json` | File identity/device riusato dal backend per firmare o autenticarsi verso OpenClaw. | Se non vuoi condividere l'identità col client CLI, usa `OPENCLAW_STATE_DIR` opzionale. |

## 6) Policy BFF / agent isolation / shared files

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `BFF_ALLOW_CLIENT_SESSION_KEY` | `false` | Flag legacy per consentire al client di passare una session key OpenClaw raw. | In generale va lasciato disabilitato per ridurre rischio IDOR. **Nota importante:** il runtime Pydantic legge `ALLOW_RAW_OPENCLAW_SESSION_KEY`. |
| `OPENCLAW_DEFAULT_AGENT_ID` | `main` | Agent di default usato quando il client non specifica un agent/model. | Cambialo se il tuo deployment ha un agente di ingresso diverso. |
| `AGENT_WORKSPACE_ROOT` | `/tmp/openclaw-bff/agents` | Root filesystem dei workspace agente, organizzati per namespace utente. | In produzione conviene usare un path persistente e scrivibile, non `/tmp`. |
| `AGENT_NAMESPACE_SALT` | `dev-namespace-salt` | Salt usato per derivare il namespace hash-only dell'utente (`u-<hash>`). | Variabile critica: se cambia, cambia il namespace e potresti perdere visibilità degli agenti esistenti. |
| `AGENT_NAMESPACE_ALLOW_LEGACY` | `true` | Permette di riconoscere anche namespace legacy slug+hash in lettura/ownership. | Tienilo `true` durante migrazioni da workspace vecchi; valuta `false` solo quando sei sicuro di non averne più bisogno. |
| `SHARED_FILES_ROOT` | `/tmp/openclaw-bff/shared-files` | Root filesystem dei file condivisi serviti pubblicamente dal backend. | In produzione usa un volume persistente e scrivibile; se il path è errato i download andranno in `404`. |
| `SHARED_FILES_URL_PREFIX` | `/shared/files` | Prefisso URL pubblico della rotta che serve i file sotto `SHARED_FILES_ROOT`. | Se lo cambi, cambia anche l'URL pubblico di tutti i download e serve un restart del backend. |

## 7) Test

| Variabile | Valore in `.env.example` | Significato | Quando cambiarla / note |
|---|---|---|---|
| `BASE_URL` | `http://localhost:8000` | Base URL usata dalla suite test per chiamare il backend in esecuzione. | In CI o in ambienti remoti impostala all'endpoint reale sotto test. |

## Variabili opzionali commentate in `.env.example`

Queste righe non sono attive di default nel file example, ma vale la pena conoscerle.

| Variabile | Esempio commentato | Significato | Quando abilitarla |
|---|---|---|---|
| `OPENCLAW_WS_DEBUG_RUNID` | `49c43345e7a449bcae4f92f0810c36e1` | Restringe il debug WS a uno specifico `runId`. | Utile solo durante troubleshooting mirato. |
| `OPENCLAW_STATE_DIR` | `~/.openclaw-bff` | Directory alternativa dove il backend può mantenere stato/identity separati dalla CLI OpenClaw. | Usala se non vuoi riusare `OPENCLAW_IDENTITY_FILE` condiviso. |
| `OPENCLAW_DEVICE_ID` | *(vuoto)* | Device ID esplicito per autenticazione/signing verso OpenClaw. | Serve solo in setup avanzati dove l'identity è passata via env invece che file. |
| `OPENCLAW_DEVICE_PRIVATE_KEY_B64` | *(vuoto)* | Chiave privata device in base64 per OpenClaw. | Variabile altamente sensibile: usala solo se richiesto dalla tua integrazione. |
| `RUN_OPENCLOW_TESTS` | `true` / `false` | Flag opzionale per abilitare o disabilitare test OpenClaw-dependent in futuro. | Oggi è documentata come possibilità futura/controllo di suite. |

## Valori alternativi mostrati nel file example

- `OPENCLAW_CLIENT_ID` e `OPENCLAW_CLIENT_MODE` mostrano anche esempi commentati per coppie come `tui` / `tui` e `webchat` / `webchat`.
- Questi esempi servono a far capire che il backend può presentarsi a OpenClaw con profili diversi, ma il valore attivo di default nel file example resta `gateway-client` + `backend`.

## Variabili runtime aggiuntive non presenti in `.env.example`

Queste variabili non compaiono oggi nel file example, ma il backend le legge davvero. Se devi fare tuning fine di runtime, autenticazione o upload, considera anche queste.

| Variabile runtime | Default runtime | Dove viene letta | Significato / note |
|---|---|---|---|
| `APP_NAME` | `OpenClaw BFF` | `app/core/config.py` | Nome applicativo esposto da FastAPI/log. Utile per branding o log multi-servizio. |
| `APP_ENV` | `local` | `app/core/config.py` | Nome ambiente runtime reale letto dal backend. È il corrispettivo effettivo di `BFF_ENV`. |
| `LOG_LEVEL` | `INFO` | `app/core/config.py` | Livello di logging runtime reale letto dal backend. È il corrispettivo effettivo di `BFF_LOG_LEVEL`. |
| `CORS_ALLOW_ORIGINS` | `*` | `app/core/config.py` | Lista origini CORS runtime reale letta dal backend. È il corrispettivo effettivo di `BFF_CORS_ORIGINS`. |
| `DB_ECHO` | `false` | `app/core/config.py` | Se `true`, SQLAlchemy logga le query SQL. Utile per debug locale, sconsigliato in produzione. |
| `MINIO_REGION` | `us-east-1` | `app/core/config.py` | Regione MinIO/S3 usata dal client. In molti setup locali può restare default. |
| `OPENCLAW_USE_DEVICE_TOKEN` | `true` | `app/core/config.py` | Flag runtime per uso device token/identity verso OpenClaw. Toccala solo se conosci il tuo handshake gateway. |
| `OPENCLAW_WS_CONNECT_TIMEOUT` | `10.0` | `app/core/config.py` e `app/core/openclaw_ws.py` | Timeout di connessione WebSocket verso OpenClaw. Aumentalo se hai reti lente o gateway distante. |
| `OPENCLAW_WS_RPC_TIMEOUT` | `20.0` | `app/core/config.py` e `app/core/openclaw_ws.py` | Timeout generale RPC WebSocket. Se troppo basso, operazioni lente possono fallire prematuramente. |
| `OPENCLAW_WS_CHALLENGE_TIMEOUT` | `2.0` | `app/core/config.py` | Timeout challenge handshake. Utile solo in tuning fine del connect flow. |
| `KEYCLOAK_VERIFY_AUD` | `true` | `app/core/config.py` | Se `true`, il backend verifica l'audience dei JWT. Disabilitarlo riduce sicurezza ed è da fare solo con piena consapevolezza. |
| `KEYCLOAK_VERIFY_ISS` | `true` | `app/core/config.py` | Se `true`, il backend verifica l'issuer dei JWT. Disabilitarlo riduce sicurezza ed è normalmente sconsigliato. |
| `ALLOW_RAW_OPENCLAW_SESSION_KEY` | `false` | `app/core/config.py` | Nome runtime reale del flag legacy di forwarding session key raw. È la controparte effettiva di `BFF_ALLOW_CLIENT_SESSION_KEY`. |
| `PERSIST_STREAMED_MESSAGES` | `true` | `app/core/config.py` | Controlla se i messaggi ricevuti via streaming vengono persistiti nel backend. |
| `UPLOAD_MAX_BYTES` | `10000000` | `app/core/config.py` | Dimensione massima consentita per upload knowledge/upload endpoints. In produzione va allineata anche a proxy/gateway. |
| `UPLOAD_PRESIGN_PUT_EXPIRES_SECONDS` | `900` | `app/core/config.py` | Scadenza runtime reale delle URL presigned PUT. |
| `UPLOAD_PRESIGN_GET_EXPIRES_SECONDS` | `3600` | `app/core/config.py` | Scadenza runtime reale delle URL presigned GET. |
| `OPENCLAW_GATEWAY_TOKEN` | *(nessuno)* | `app/core/openclaw_ws.py` | Fallback token letto se `OPENCLAW_BEARER_TOKEN` non è valorizzata. Variabile legacy/fallback. |
| `OPENCLAW_BFF_STATE_DIR` | *(nessuno, fallback a `~/.openclaw-bff`)* | `app/core/openclaw_ws.py` | Nome alternativo legacy per la directory di stato locale del BFF. |
| `OPENCLAW_LOCALE` | `en-US` | `app/core/openclaw_ws.py` | Locale dichiarata nell'handshake `connect` verso OpenClaw. |
| `OPENCLAW_USER_AGENT` | `openclaw-bff/0.1.0` | `app/core/openclaw_ws.py` | User-Agent dichiarato nell'handshake verso OpenClaw. |
| `OPENCLAW_WS_DEBUG_MAX_CHARS` | `20000` | `app/core/openclaw_ws.py` | Limite massimo di caratteri stampati nei payload di debug WS. Utile per non esplodere i log. |

## Mappature e differenze importanti da sapere

Questa sezione è importante perché `.env.example` e il codice runtime non sono perfettamente allineati su tutti i nomi.

| Nome presente in `.env.example` | Nome letto dal runtime / nota |
|---|---|
| `BFF_ENV` | Il runtime Pydantic oggi legge `APP_ENV`. |
| `BFF_LOG_LEVEL` | Il runtime Pydantic oggi legge `LOG_LEVEL`. |
| `BFF_CORS_ORIGINS` | Il runtime Pydantic oggi legge `CORS_ALLOW_ORIGINS`. |
| `BFF_ALLOW_CLIENT_SESSION_KEY` | Il runtime Pydantic oggi legge `ALLOW_RAW_OPENCLAW_SESSION_KEY`. |
| `MINIO_PRESIGN_EXPIRE_SECONDS` | Il runtime Pydantic oggi espone `UPLOAD_PRESIGN_PUT_EXPIRES_SECONDS` e `UPLOAD_PRESIGN_GET_EXPIRES_SECONDS`. |

### Impatto pratico delle differenze

- Se vuoi la massima prevedibilità in deploy, mantieni coerenti sia i nomi mostrati in `.env.example` sia quelli effettivamente letti dal runtime.
- In particolare, per logging/ambiente/CORS/allow raw session key, verifica se il tuo deployment sta valorizzando le variabili runtime corrette.
- Le variabili nuove per agent isolation e shared files (`AGENT_*`, `SHARED_FILES_*`, `BFF_PUBLIC_BASE_URL`) sono invece parte importante del comportamento attuale e vanno impostate esplicitamente nei deploy reali.

## Regola di manutenzione

Quando aggiungi o rimuovi una variabile in `.env.example`, aggiorna anche questa pagina e i link in `README.md` / `docs/RUNBOOK.md`.
