# Web UI

The web UI runs at `http://localhost:8888` and exposes all tools through a tabbed interface inspired by Burp Suite.

## Theme

Toggle between dark (obsidian/blue) and light mode using the button in the top-right corner. The preference is saved across sessions.

## Tabs

| Tab | What it does |
|---|---|
| **Dashboard** | Overview cards and quick-launch tool buttons |
| **Proxy** | Live HTTP traffic log from the intercepting proxy |
| **Intruder** | Burp Intruder-style fuzzer (CLI — see Intruder tab for command) |
| **Repeater** | Resend and modify individual HTTP requests |
| **Sequencer** | Token entropy analysis (Shannon, bit-level, monobit) |
| **Decoder** | Encode/decode: URL, Base64, HTML, hex, hex-escape |
| **Comparer** | Unified diff between two text blocks |
| **JWT** | Decode, alg:none attack, claim tampering, HMAC crack |
| **Spider** | BFS crawler — finds pages, links, files, external URLs |
| **Param Miner** | Discover hidden HTTP parameters from a wordlist |
| **CSRF PoC** | Generate auto-submit HTML PoC from a raw Burp request |

## API

Every tab posts to a local REST endpoint:

```
POST /api/<tool>   Content-Type: application/json
```

The server returns JSON. All processing is local — no data leaves your machine.
