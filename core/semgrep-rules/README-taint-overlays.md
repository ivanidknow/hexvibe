# Optional Semgrep taint overlays (v1.0)

For **data-flow** from IPC entrypoints to dangerous sinks (Electron `ipcMain` → `eval` / `child_process`), enable a **taint-mode** rule in CI or locally.

Example (not bundled in the 1000-ID gold matrix to keep `detection-summary.json` stable):

```yaml
rules:
  - id: hexvibe.local.electron.ipc-to-exec
    languages: [javascript, typescript]
    mode: taint
    message: IPC data may reach exec/eval — validate senderFrame/origin.
    pattern-sources:
      - pattern: ipcMain.on($E, $H)
      - pattern: ipcMain.handle($C, $H)
    pattern-sinks:
      - pattern: eval($X)
      - pattern: child_process.exec($X, ...)
```

Map to MITRE **T1059.007** (JavaScript) / **T1204** where applicable; combine with `server/cognitive_engine.py` to downgrade confidence when matches are constant-only.
