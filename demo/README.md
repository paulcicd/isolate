# Isolate v2 Docker Demo

Полностью локальное disposable-окружение для проверки Isolate v2. В stack входят:

- Ubuntu 24.04 bastion с Linux-пользователями `alice` и `bob`;
- Keycloak с Device Authorization Grant для CLI и Authorization Code Flow для dashboard;
- Redis с пятью hosts, project sets и grants;
- пять Alpine SSH targets с пользователями `support`, `dev` и `dba`;
- web dashboard, history, replay, active-session control и structured command audit.

Это только demo. Пароли, client secret, HTTP и статические адреса намеренно упрощены и не подходят для production.

## Требования

- Docker Desktop или Docker Engine с Compose v2;
- свободные локальные порты `18080`, `18081` и `2222`;
- примерно 2 GB свободной RAM, основную часть использует Keycloak.

## Быстрый запуск

Из корня репозитория:

```bash
docker compose -f demo/docker-compose.yml up -d --build
docker compose -f demo/docker-compose.yml ps
docker compose -f demo/docker-compose.yml --profile tools run --rm smoke
```

Первый build и старт Keycloak могут занять несколько минут. Состояние сервисов:

```bash
docker compose -f demo/docker-compose.yml logs -f keycloak bastion dashboard
```

После успешного smoke test доступны:

| Сервис | URL / команда |
| --- | --- |
| Keycloak | `http://localhost:18080` |
| Keycloak Admin Console | `http://localhost:18080/admin` |
| Isolate dashboard | `http://localhost:18081` |
| Bastion SSH | `ssh -p 2222 alice@localhost` |

## Учётные данные

| Назначение | Логин | Пароль | Группы |
| --- | --- | --- | --- |
| Bastion Linux + Keycloak admin-user | `alice` | `demo123` | `Demo-DevOps` |
| Bastion Linux + Keycloak restricted-user | `bob` | `demo123` | `Demo-Developers`, `Demo-DBA` |
| Keycloak Admin Console | `admin` | `admin123` | realm administrator |

Linux и Keycloak являются отдельными identity layers, хотя в demo у них одинаковые имена и пароли.

## CLI: Alice

Подключитесь к bastion:

```bash
ssh -p 2222 alice@localhost
```

Затем запустите login:

```bash
isolate login
```

Откройте напечатанный URL в локальном браузере и войдите как `alice` / `demo123`. После login:

```bash
isolate whoami
s .
s redis
g 10001
```

На target:

```bash
whoami
pwd
echo "hello from isolate"
exit
```

`alice` получает grant `Demo-DevOps -> project * -> remote_user support`, поэтому видит все пять hosts и подключается под `support`.

Проверка истории и structured command events:

```bash
f
isolate history --limit 10
```

## CLI: Bob

Во втором терминале:

```bash
ssh -p 2222 bob@localhost
isolate login
s .
g 10001
```

Для Device Flow используйте `bob` / `demo123`; удобнее открыть URL в приватном окне браузера. Ожидаемое поведение:

- `payments-dev` доступен через `Demo-Developers`, remote user `dev`;
- `database-prod` доступен через `Demo-DBA`, remote user `dba`;
- остальные проекты скрыты в `s` и запрещены в `g`.

```bash
g 10003
whoami
exit
g 10002
```

Последняя команда должна вернуть policy denied и подсказку для access request.

## Dashboard

Откройте `http://localhost:18081` и войдите как `alice` / `demo123`. Только группа `Demo-DevOps` входит в `dashboard.admin_groups`; вход `bob` завершится `403`.

В dashboard можно проверить:

- inventory из пяти hosts, service metadata и VIP marker;
- grants и project sets;
- policy simulator;
- активные и завершённые sessions;
- live transcript активного подключения;
- terminate request для активной session;
- history, session details, JSONL events и terminal replay;
- access request approve/deny workflow.

Чтобы увидеть active session, оставьте `g 10001` открытой в SSH-терминале и перейдите в `Active sessions`. После нескольких команд выйдите с target и откройте session details/replay из History.

## Break-glass workflow

Под `bob` запросите временный доступ к закрытому project:

```bash
isolate access request \
  --project payments-prod \
  --host 10002 \
  --remote-user support \
  --sudo-mode none \
  --reason "Demo incident" \
  --ticket INC-1001
```

Затем под `alice` одобрите request в dashboard `/access` или CLI:

```bash
isolate access list --status pending
isolate access approve --id 1 --ttl 30m --comment "Demo approval"
```

После approval `bob` сможет выполнить `g 10002` до истечения temporary grant.

## Inventory и policy CLI

```bash
isolate host list
isolate host show 10005
isolate grant list
isolate project-set list
isolate project-set show developer-projects
isolate grant explain --user alice --group Demo-DevOps --host 10005
```

Host `10005` помечен как VIP и содержит generic hint на внешний privileged access provider. Этот marker информационный и не меняет SSH routing.

## Backup smoke

На bastion:

```bash
isolate backup create --include-logs
isolate backup list
```

Архив остаётся в named volume `demo-backups` до удаления volume.

## Остановка и полный reset

Остановить с сохранением Redis/Keycloak/logs:

```bash
docker compose -f demo/docker-compose.yml down
```

Удалить всё demo-состояние и начать с чистого realm/Redis/keys/logs:

```bash
docker compose -f demo/docker-compose.yml down -v --remove-orphans
```

## Troubleshooting

Показать status и последние logs:

```bash
docker compose -f demo/docker-compose.yml ps
docker compose -f demo/docker-compose.yml logs --tail=200 keycloak demo-init target-1 bastion dashboard
```

Повторить smoke test:

```bash
docker compose -f demo/docker-compose.yml --profile tools run --rm smoke
```

Если realm JSON изменился после первого запуска, выполните полный reset с `down -v`: Keycloak не перезаписывает уже импортированный realm.
