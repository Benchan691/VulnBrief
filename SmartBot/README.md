# SmartBot Test UI

This workspace contains a simple HTML page to test SmartOA SmartBot SSE and message send endpoints.

## Run from a local HTTP server

Open a terminal in this folder and run one of these commands:

### With Python 3

```powershell
python -m http.server 8000
```

Then open:

```text
http://localhost:8000/smartbot-ui.html
```

### With Node.js

```powershell
npx http-server -p 8000
```

Then open the same URL in your browser.

## Why

Loading the page via `file://` can cause network request failures in browsers. Serving it over `http://localhost` is much more reliable for CORS and fetch requests.

## Sending a message from the command line

The Python bot now loads settings from `config.json` and accepts a message argument.

```powershell
python main.py "hello"
```

To use a different config file:

```powershell
python main.py --config custom-config.json "hello"
```
