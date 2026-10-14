# CLAUDE.md

O guia de operação deste repositório é o **[AGENTS.md](AGENTS.md)** — leia-o antes de
mexer em qualquer coisa. Em resumo, para não duplicar regras:

- Escopo validado: **Windows 10/11**. Linux/WSL e macOS são roadmap — não os descreva
  como funcionais.
- **Nada de terceiros/alvo no Git**: `work/`, `ghidra/`, `x64dbg/`, `rea-main/`,
  `.cache/`, `config/env/unboxre.env` são gitignored de propósito.
- **Nunca `sudo`**; scripts são **dry-run por padrão** (`-Apply` para agir).
- **Evidência antes de interpretação** e **licença sempre conferida na fonte primária**.
- Comece por `.\scripts\health-check.ps1 -Json` e `node scripts/check-consistency.mjs`;
  triagem de alvo com `identify-protections.mjs` e `diagnose-load.mjs`.

Detalhes, mapa do repositório, comandos e armadilhas conhecidas: [AGENTS.md](AGENTS.md).
