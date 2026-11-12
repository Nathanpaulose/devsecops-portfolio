# DevSecOps Portfolio

A small Flask room-booking app, built and secured using DevSecOps practices.

> Work in progress: the security pipeline, threat model and live deployment are being added in stages.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r app/requirements.txt -r app/requirements-dev.txt
cd app
SESSION_COOKIE_SECURE=false flask --app main run
```

On Windows PowerShell, set the variable first with `$env:SESSION_COOKIE_SECURE="false"`, then run `flask --app main run`.

Then open http://127.0.0.1:5000.

## Run the tests

```bash
cd app
python -m pytest -v
```
