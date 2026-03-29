# HexVibe v1.0 — когнитивный AppSec Guardrail

[![Platform](https://img.shields.io/badge/platform-AI--Security-blueviolet)](#возможности)
[![Architecture](https://img.shields.io/badge/arch-Threat%20Modeling%20Enabled-blue)](core/skills/)
[![Compliance](https://img.shields.io/badge/compliance-Enterprise%20Ready-success)](core/skills/)
[![Rules Count](https://img.shields.io/badge/rules-1000%20patterns-blue)](core/skills/index.md)
[![Status](https://img.shields.io/badge/status-Production%20Ready-orange)](#разработка-и-расширение)

**HexVibe** — MCP-сервер безопасности для полной автоматизации Security Code Review и защиты жизненного цикла генеративной разработки с помощью **когнитивного guardrail**. В финальные журналы попадают только проверенные находки с высоким доверием (confidence_score >= 0.8).

Текущий набор правил зафиксирован регрессией на **1000/1000 HIT** в среде `core/gold-standard-testbed/`.

---

## Архитектура (кратко)

(Схема: разработчик → HexVibe → когнитивный движок → проверенный отчёт.)

---

## Быстрый старт

### 1) Сборка и синхронизация

```bash
bash scripts/docker-publish.sh
python scripts/sync_semgrep.py
```

### 2) Запуск (Docker)

```bash
docker run -i --rm -v "${PWD}:/app" hexvibe-ai:latest
```

### 3) Интеграция в IDE

- **Cursor**: Settings → Features → MCP → Add server. Имя: HexVibe, тип: command, команда: `docker run -i --rm -v "${PWD}:/app" hexvibe-ai:latest`.
- **Claude Desktop**: скопируйте настройки из `mcp-deployment.json` в конфигурацию MCP.

### 4) Проверка

Спросите агента: «HexVibe, confirm current baseline». Ожидается подтверждение 1000 паттернов и метаданных v1.0.

---

## Когнитивный Guardrail

Реализован в `server/cognitive_engine.py`. Анализ состоит из трёх фаз:

- **Фаза 1 — исследование контекста**: сигналы в файлах и манифестах (`package.json`, `requirements.txt`, `pyproject.toml`) с подъёмом к корню репозитория.
- **Фаза 2 — анализ доверия**: базовый скоринг с бонусом +0.2 при расхождении кода со стеком, жёсткие исключения и база прецедентов для подавления шума.
- **Фаза 3 — самокритика**: финальная проверка через `extra.cognitive.self_critique` и реальные цепочки атак (`attack_path_concrete`).

---

## Официальный baseline

| Метрика | Значение |
| :--- | :--- |
| Идентификаторы правил | 1000 |
| Точность (gold matrix) | 1000 / 1000 HIT |
| Домены безопасности | 22 |
| Покрытие CWE (паттерны) | >= 138 |
| Автоисправления (Autofix) | 1000 / 1000 |

---

## Возможности

- **Интерактивное моделирование угроз (STRIDE)** и архитектурный cross-check с пометками **[CONFIRMED]** / **[REQUIRES VERIFICATION]**.
- **Когнитивный Guardrail**: три фазы (исследование → скоринг → самокритика), фильтрация ложных срабатываний с учётом **enterprise**-контекста.
- **Smart Autofix**: контекстные исправления для всех 1000 паттернов.
- **Покрытие стеков**: IPC, API, утечки в AI SDK, безопасная обработка документов.
- **MCP + Docker**: Semgrep, TruffleHog, Syft; полный цикл сканирования в `server/adapter.py`.

---

## Соответствие и стандарты

Документация и правила сформулированы в терминах **Enterprise Compliance** и **High-Security Standards**: персональные данные, резидентность, криптография и инфраструктурные контроли описаны нейтрально, без привязки к отдельным отраслевым или внутренним базовым линиям.

---

## Сценарии использования

### Сценарий A: Guardrail в рантайме

Используйте HexVibe как «предохранитель» при генерации кода ИИ.

### Сценарий B: Security Review

Полный обзор репозитория перед релизом: STRIDE, поиск логических ошибок, подтверждение в коде.

---

## Разработка и расширение

- **Правила**: правьте `patterns.md` в нужном домене и выполните `python scripts/sync_semgrep.py`.
- **Тестовый стенд**: добавляйте PoC в `core/gold-standard-testbed/` с маркерами `Vulnerable: PREFIX-NNN`.

---

## Принципы безопасности

Помечайте PoC тегом `Vulnerable: PREFIX-NNN`; используйте те же ID при ревью. Не публикуйте известные нарушения без отдельного исключения.
