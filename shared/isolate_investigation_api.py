"""Authenticated chronological investigation view of scoped audit evidence."""
import datetime
import html
import json
import sqlite3
from urllib.parse import urlencode

from isolate_investigations import InvestigationError, KINDS, STAGES, timeline


def register_investigation_api(app, config, runtime_factory, bearer, failure, errors):
    from flask import abort, jsonify, request

    def read(browser=False):
        token = bearer(allow_browser=True)
        if not config.get('audit_index', {}).get('enabled'):
            abort(404)
        filters = request.args.to_dict()
        if browser:
            for name, target in (('from', 'since'), ('to', 'until')):
                value = filters.pop(name, '')
                if value:
                    try:
                        filters[target] = datetime.datetime.fromisoformat(value).replace(tzinfo=datetime.timezone.utc).timestamp()
                    except ValueError:
                        raise InvestigationError('invalid UTC date') from None
        if filters.get('before'):
            try:
                filters['before'] = json.loads(filters['before'])
            except (ValueError, TypeError):
                raise InvestigationError('invalid timeline cursor') from None
        if 'related' in filters:
            if filters['related'] not in ('true', 'false'):
                raise InvestigationError('related must be true or false')
            filters['related'] = filters['related'] == 'true'
        control = runtime_factory()
        identity = control.authenticate(token)
        from isolate_workflow_audit import publish_pending
        publication = publish_pending(control.redis, config)
        if publication['failed']:
            raise sqlite3.OperationalError('workflow evidence publication is unavailable')
        return timeline(config, identity, filters)

    def unavailable():
        return jsonify(error='investigation_evidence_unavailable'), 503

    @app.get('/api/v1/investigations/timeline')
    def api_investigation_timeline():
        try:
            return jsonify(read())
        except InvestigationError as exc:
            return jsonify(error='invalid_investigation', message=str(exc)), 400
        except sqlite3.Error:
            return unavailable()
        except errors as exc:
            return failure(exc)

    @app.get('/investigations')
    def investigation_page():
        import isolate_web
        try:
            result = read(browser=True)
        except InvestigationError as exc:
            return isolate_web._html('Investigation', '<h1>Check investigation filters</h1><p>{}</p>'.format(html.escape(str(exc))), config=config), 400
        except sqlite3.Error:
            return unavailable()
        except errors as exc:
            return failure(exc)
        e = lambda value: html.escape(str(value), quote=True)
        russian = isolate_web._dashboard_locale(config) == 'ru'
        title = 'Расследование' if russian else 'Investigation'
        stage_labels = dict(zip(STAGES, ('Вход', 'Доступ', 'Согласование', 'Сессия', 'Команда', 'Результат') if russian
            else ('Sign-in', 'Access', 'Approval', 'Session', 'Command', 'Result')))
        body = '<h1>{}</h1><p class="page-lead">{}</p>'.format(title,
            'Связанная история действий в пределах ваших прав. Связи построены по явным идентификаторам.' if russian
            else 'Follow related actions within your current access scope. Relationships use explicit identifiers.')
        body += '<form method="get" class="investigation-filters"><label>{}<select name="kind"><option value="">{}</option>'.format(
            'Объект' if russian else 'Object', 'Все события' if russian else 'All events')
        labels = {'connection': 'Session', 'request': 'Access request', 'approval': 'Session approval', 'job': 'Job',
                  'campaign': 'Runbook campaign', 'grant': 'Grant', 'identity-session': 'Sign-in session'}
        for kind in KINDS:
            body += '<option value="{}" {}>{}</option>'.format(kind, 'selected' if request.args.get('kind') == kind else '', e(labels[kind]))
        body += '</select></label>'
        for name, label in (('id', 'ID'), ('subject', 'Person / stable ID'), ('project', 'Project'), ('host_id', 'Resource ID')):
            body += '<label>{}<input name="{}" maxlength="256" value="{}"></label>'.format(e(label), name, e(request.args.get(name, '')))
        for name, label in (('from', 'From (UTC)'), ('to', 'To (UTC)')):
            body += '<label>{}<input type="datetime-local" name="{}" value="{}"></label>'.format(label, name, e(request.args.get(name, '')))
        body += '<button type="submit">{}</button></form>'.format('Показать' if russian else 'Show timeline')
        body += '<ol class="investigation-stages" aria-label="Lifecycle">'
        for phase in STAGES:
            body += '<li data-observed="{}">{}</li>'.format(str(phase in result['coverage']['observed']).lower(), e(stage_labels[phase]))
        body += '</ol><p class="muted">{}</p>'.format('Показана последняя страница, от ранних событий к поздним. Отсутствие события не подтверждает отсутствие действия.' if russian
            else 'Latest page, from earlier to later events. A missing event does not establish that an action did not occur.')
        body += '<ol class="investigation-events">'
        for record in result['events']:
            timestamp = datetime.datetime.fromtimestamp(float(record['ts']), datetime.timezone.utc).isoformat(timespec='seconds')
            body += '<li class="investigation-event"><article><header><time datetime="{}">{}</time> · <strong>{}</strong></header>'.format(
                e(timestamp), e(timestamp), e(stage_labels[record['stage']]))
            if record.get('timestamp_source') == 'index-ingestion':
                body += '<p class="muted">{}</p>'.format('Время индексирования; исходное событие не содержит времени.' if russian
                    else 'Indexing time; the source event did not contain an event timestamp.')
            body += '<p>{} · {} · {}</p>'.format(e(record.get('event', '')), e(record.get('username', '')), e(record.get('project', '')))
            if record.get('status') or record.get('result') or record.get('outcome'):
                body += '<p>{}</p>'.format(e(record.get('status') or record.get('result') or record.get('outcome')))
            body += '<details><summary>{}</summary><pre>{}</pre></details>'.format('Данные события' if russian else 'Event details',
                html.escape(json.dumps({k: v for k, v in record.items() if k != 'links'}, ensure_ascii=False, indent=2)))
            for name, link in record['links'].items():
                body += '<a href="{}">{}</a> '.format(e(link), e(record.get(name)))
            body += '</article></li>'
        body += '</ol>'
        if not result['events']:
            body += '<p role="status">{}</p>'.format('Видимых событий не найдено.' if russian else 'No visible events match these filters.')
        if result['expansion_bounded']:
            body += '<p role="status">{}</p>'.format('Связанная выборка достигла лимита. Уточните объект или период.' if russian
                else 'Related evidence reached its bound. Narrow the object or time range.')
        if result['next']:
            values = dict(request.args)
            values['before'] = json.dumps(result['next'])
            body += '<p><a href="?{}">{}</a></p>'.format(e(urlencode(values)), 'Ранее' if russian else 'Earlier events')
        body += '''<style>.investigation-filters{display:flex;gap:12px;flex-wrap:wrap;align-items:end}.investigation-filters label{display:grid;gap:5px}
.investigation-stages{display:flex;gap:8px;flex-wrap:wrap;padding:16px 0;list-style:none}.investigation-stages li{padding:6px 12px;border:1px solid var(--line);border-radius:20px}
.investigation-stages [data-observed=true]{background:var(--accent-soft);border-color:var(--accent)}.investigation-events{list-style:none;padding:0;border-left:2px solid var(--line);margin-left:8px}
.investigation-event{padding:0 0 22px 22px;overflow-wrap:anywhere}.investigation-event article{padding:16px;border:1px solid var(--line);border-radius:10px}.investigation-event pre{white-space:pre-wrap}</style>'''
        return isolate_web._html(title, body, config=config)
