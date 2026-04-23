# Docling Markdown Demo

Demo completo per convertire documenti complessi in **Markdown** usando **Docling**, con una classe Python riusabile e uno script di esecuzione che processa più file in batch.

Il progetto è pensato per mostrare una pipeline semplice ma realistica per casi d'uso tipo:

- ingestion documentale verso LLM
- conversione di documenti Office e PDF in `.md`
- test comparativi su file con layout, tabelle, immagini e sezioni multiple
- sperimentazione OCR opzionale sui PDF

---

## 1. Contenuto del pacchetto

La struttura del progetto è questa:

```text
/docling_markdown_demo
├── README.md
├── requirements.txt
├── assets/
│   ├── analytics_banner.png
│   └── logistics_isometric.png
├── inputs/
│   ├── complex_program_brief.docx
│   ├── complex_operations_dashboard.xlsx
│   ├── complex_steering_committee_update.pptx
│   └── complex_supplier_resilience_assessment.pdf
├── outputs/
├── qa/
│   ├── docx_render/
│   ├── pdf_render/
│   ├── ppt_pdf/
│   └── ppt_render/
└── scripts/
    ├── create_sample_documents.py
    ├── docling_converter.py
    └── run_docling_demo.py
```

### Cartelle principali

#### `inputs/`
Contiene i 4 file complessi usati per la demo:

- `complex_program_brief.docx`
- `complex_operations_dashboard.xlsx`
- `complex_steering_committee_update.pptx`
- `complex_supplier_resilience_assessment.pdf`

#### `scripts/`
Contiene il codice Python della demo.

- `create_sample_documents.py` rigenera i file di esempio.
- `docling_converter.py` implementa la classe `DoclingMarkdownConverter`.
- `run_docling_demo.py` usa la classe per processare i file di test e scrivere i `.md`.

#### `outputs/`
È la cartella di destinazione dei file Markdown generati.

#### `assets/`
Contiene immagini usate nei documenti campione.

#### `qa/`
Contiene materiali di **quality assurance**, cioè render e anteprime per verificare visivamente i file di test.
Non è necessaria per l’esecuzione della conversione.

In particolare:

- `qa/docx_render/`: anteprime PNG del DOCX
- `qa/pdf_render/`: anteprime PNG del PDF
- `qa/ppt_pdf/`: versione PDF della presentazione
- `qa/ppt_render/`: render PNG delle slide

---

## 2. Cosa fa la demo

La demo implementa una pipeline molto semplice:

1. legge i documenti da `inputs/`
2. usa **Docling** per convertirli in Markdown
3. salva i file `.md` in una cartella di output
4. salva anche file `.json` con metadati minimi
5. salva un riepilogo generale in `conversion_summary.json`

I formati gestiti dalla classe inclusa nel progetto sono:

- `.docx`
- `.xlsx`
- `.pptx`
- `.pdf`

---

## 3. Prerequisiti

Per lanciare la demo ti servono:

- Python 3.10+
- `pip`
- un ambiente virtuale Python consigliato
- accesso internet durante l’installazione delle dipendenze

La demo usa Docling in modalità **CPU-only** tramite indice PyTorch CPU nel file `requirements.txt`.

---

## 4. Installazione

### 4.1 Estrai lo ZIP

Se hai ricevuto un file ZIP, estrailo e posizionati nella cartella del progetto.

Esempio:

```bash
unzip docling_markdown_demo_bundle.zip -d docling_markdown_demo
cd docling_markdown_demo
```

### 4.2 Crea un ambiente virtuale

Su Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Su Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 4.3 Aggiorna pip

```bash
pip install --upgrade pip setuptools wheel
```

### 4.4 Installa le dipendenze

```bash
pip install -r requirements.txt
```

Il file `requirements.txt` contiene:

```text
--extra-index-url https://download.pytorch.org/whl/cpu
docling
python-docx
openpyxl
python-pptx
reportlab
Pillow
```

Questo installa:

- `docling` per la conversione in Markdown
- `python-docx`, `openpyxl`, `python-pptx`, `reportlab`, `Pillow` per creare e rigenerare i file sample

---

## 5. Verifica rapida dell’installazione

Per controllare che Docling sia importabile:

```bash
python -c "import docling; print('Docling installato correttamente')"
```

Per controllare che la CLI sia disponibile:

```bash
docling --help
```

Se questi comandi funzionano, l’ambiente è pronto.

---

## 6. Come lanciare la demo

### Metodo consigliato: eseguire tutti i file di esempio

Da dentro la root del progetto:

```bash
python scripts/run_docling_demo.py --output-dir outputs
```

Questo comando:

- legge automaticamente i 4 file in `inputs/`
- li converte con `DoclingMarkdownConverter`
- scrive i file `.md` dentro `outputs/`

### Risultati attesi

Nella cartella `outputs/` troverai:

- `complex_program_brief.md`
- `complex_operations_dashboard.md`
- `complex_steering_committee_update.md`
- `complex_supplier_resilience_assessment.md`

In aggiunta troverai anche:

- un file `.json` per ciascun documento convertito
- `conversion_summary.json` con il riepilogo finale

---

## 7. Comandi principali

### 7.1 Convertire tutti i file demo

```bash
python scripts/run_docling_demo.py --output-dir outputs
```

### 7.2 Convertire tutti i file demo con OCR per i PDF

```bash
python scripts/run_docling_demo.py --output-dir outputs --ocr
```

### 7.3 Convertire tutti i file demo con OCR pieno su ogni pagina PDF

```bash
python scripts/run_docling_demo.py --output-dir outputs --ocr --force-full-page-ocr
```

Nota: l’opzione `--force-full-page-ocr` dipende dalla versione di Docling installata. Se la tua versione non la supporta, la classe prova a degradare in modo sicuro.

### 7.4 Continuare anche se un file fallisce

```bash
python scripts/run_docling_demo.py --output-dir outputs --continue-on-error
```

### 7.5 Usare una cartella input personalizzata

```bash
python scripts/run_docling_demo.py --input-dir /path/ai/miei/input --output-dir /path/output
```

---

## 8. Usare direttamente la classe converter

Puoi usare lo script `docling_converter.py` direttamente su uno o più file.

### 8.1 Convertire un solo file

```bash
python scripts/docling_converter.py inputs/complex_program_brief.docx --output-dir outputs
```

### 8.2 Convertire più file insieme

```bash
python scripts/docling_converter.py \
  inputs/complex_program_brief.docx \
  inputs/complex_operations_dashboard.xlsx \
  inputs/complex_steering_committee_update.pptx \
  inputs/complex_supplier_resilience_assessment.pdf \
  --output-dir outputs
```

### 8.3 Convertire un PDF con OCR

```bash
python scripts/docling_converter.py \
  inputs/complex_supplier_resilience_assessment.pdf \
  --output-dir outputs \
  --ocr
```

### 8.4 Convertire più file e non fermarsi al primo errore

```bash
python scripts/docling_converter.py \
  inputs/complex_program_brief.docx \
  inputs/complex_operations_dashboard.xlsx \
  --output-dir outputs \
  --continue-on-error
```

---

## 9. Rigenerare i documenti di esempio

Se vuoi ricreare i file demo da zero:

```bash
python scripts/create_sample_documents.py
```

Questo script ricostruisce:

- il DOCX complesso
- il file Excel con fogli, grafici e formattazione
- il PowerPoint con slide strutturate
- il PDF complesso
- gli asset di supporto, se disponibili

### Quando usare questo script

Usalo se:

- vuoi modificare i file sample
- vuoi rifare il dataset di test
- vuoi estendere la demo con nuovi pattern documentali

Non è necessario eseguirlo per lanciare la demo standard, perché i file sono già inclusi in `inputs/`.

---

## 10. Output generati

Per ogni documento convertito, la demo produce almeno due file.

### 10.1 File Markdown

Esempio:

```text
outputs/complex_program_brief.md
```

È il contenuto convertito in Markdown da Docling.

### 10.2 File JSON di metadati

Esempio:

```text
outputs/complex_program_brief.json
```

Contiene metadati come:

- nome file sorgente
- estensione sorgente
- nome file di output
- OCR richiesto o no
- eventuali note della configurazione del converter

### 10.3 File di riepilogo globale

```text
outputs/conversion_summary.json
```

Contiene una lista con:

- file sorgente
- file Markdown di output
- stato (`ok` oppure `error`)
- eventuali note

---

## 11. Come funziona la classe `DoclingMarkdownConverter`

La classe si trova in:

```text
scripts/docling_converter.py
```

### Responsabilità principali

La classe:

- controlla che il file sia supportato
- istanzia Docling
- abilita OCR opzionale per i PDF
- converte il documento
- esporta il contenuto in Markdown
- salva output e metadati
- produce un report di conversione

### Formati supportati nella demo

```python
SUPPORTED_SUFFIXES = {".pdf", ".docx", ".xlsx", ".pptx"}
```

### Comportamento OCR

- se non passi `--ocr`, usa un `DocumentConverter()` standard
- se passi `--ocr`, prova a configurare `PdfPipelineOptions()` con `do_ocr = True`
- se la configurazione OCR fallisce per incompatibilità di versione, prova a usare comunque il converter standard

Questo rende la demo più robusta rispetto a differenze tra versioni di Docling.

---

## 12. Esempio di flusso completo

Su Linux/macOS:

```bash
cd docling_markdown_demo
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
python scripts/run_docling_demo.py --output-dir outputs
```

Su Windows PowerShell:

```powershell
cd docling_markdown_demo
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
python scripts\run_docling_demo.py --output-dir outputs
```

---

## 13. Troubleshooting

### Problema: `ModuleNotFoundError: No module named 'docling'`

Soluzione:

- verifica di aver attivato il venv
- reinstalla con:

```bash
pip install -r requirements.txt
```

### Problema: `docling --help` non funziona

Soluzione:

- verifica che il venv sia attivo
- prova:

```bash
python -m pip show docling
```

### Problema: il runner si ferma al primo errore

Usa:

```bash
python scripts/run_docling_demo.py --output-dir outputs --continue-on-error
```

### Problema: l’OCR non sembra attivo

Prova:

```bash
python scripts/run_docling_demo.py --output-dir outputs --ocr
```

oppure:

```bash
python scripts/run_docling_demo.py --output-dir outputs --ocr --force-full-page-ocr
```

### Problema: vuoi ripartire da zero

Cancella i risultati precedenti:

```bash
rm -rf outputs/*
```

poi rilancia:

```bash
python scripts/run_docling_demo.py --output-dir outputs
```

---

## 14. Note importanti

### La cartella `qa` non è necessaria alla conversione

Serve solo come supporto visivo e controllo qualità dei documenti di input.

### Gli `assets/` sono usati per rendere i documenti demo più realistici

Non sono necessari alla conversione finale, ma servono per generare i file sample.

### La demo è pensata per essere estendibile

Puoi facilmente:

- aggiungere nuovi file in `inputs/`
- ampliare `SUPPORTED_SUFFIXES`
- personalizzare la configurazione OCR
- aggiungere output JSON più ricchi
- integrare logging, fallback engine e benchmark

---

## 15. File chiave da conoscere

Se vuoi orientarti rapidamente, questi sono i file più importanti.

### Per eseguire la demo

- `requirements.txt`
- `scripts/run_docling_demo.py`

### Per capire la logica di conversione

- `scripts/docling_converter.py`

### Per ispezionare gli input

- `inputs/complex_program_brief.docx`
- `inputs/complex_operations_dashboard.xlsx`
- `inputs/complex_steering_committee_update.pptx`
- `inputs/complex_supplier_resilience_assessment.pdf`

### Per rigenerare tutto

- `scripts/create_sample_documents.py`

---

## 16. Comando consigliato per partire subito

Questo è il comando più semplice per testare subito tutto il pacchetto dopo l’installazione:

```bash
python scripts/run_docling_demo.py --output-dir outputs
```

Se vuoi testare anche OCR sui PDF:

```bash
python scripts/run_docling_demo.py --output-dir outputs --ocr
```

---

## 17. Possibili estensioni future

Il progetto si presta facilmente ad aggiunte come:

- supporto a OCR custom
- esportazione parallela `.md` + `.json`
- Dockerfile
- Makefile
- benchmark automatici
- logging strutturato
- confronto tra Docling e altri engine
- supporto a input directory generiche per batch processing

---

## 18. Sintesi finale

Questo bundle ti permette di:

- installare rapidamente un ambiente Docling CPU-only
- testare la conversione Markdown su 4 documenti complessi
- usare una classe Python riusabile per conversione batch
- sperimentare OCR opzionale sui PDF
- ottenere output `.md` pronti da ispezionare o inviare a pipeline LLM

