# AAS VPN

Готовый стек для собственного VPN:

- AmneziaWG (`wg-easy` v15);
- личный кабинет выдачи конфигов по подтверждению номера через Zvonok;
- белый список телефонов и индивидуальный лимит устройств;
- QR-код и загрузка `.conf` для каждого устройства;
- AdGuard Home и четыре независимых DNS-over-HTTPS upstream;
- sing-box: обычный выход через основной VPS, домены РФ — через `wg-ru`;
- Caddy/HTTPS и watchdog с одним повтором перед восстановлением.

## Сеть и порты

TCP 80/443 занимает Caddy. UDP 443 занимает AmneziaWG — конфликта нет, потому что это разные протоколы. Панель AWG и пользовательский портал могут работать на разных доменах через один TCP/443.

## Быстрая установка

Требуются Debian 12+/Ubuntu 22.04+, root, Docker Compose и две A-записи на IP сервера: домен панели и домен портала.

```bash
git clone https://github.com/NikoVonLas/aas-vpn.git
cd aas-vpn
cp .env.example .env
nano .env
sudo ./scripts/deploy.sh
```

Обязательные параметры `.env`:

- `VPN_DOMAIN` — домен панели wg-easy;
- `PORTAL_DOMAIN` — публичный портал (можно корневой домен);
- `ZVONOK_PUBLIC_KEY` и `ZVONOK_CAMPAIGN_ID` кампании «Звонок на проверочный номер»;
- логин, пароль и TOTP secret панели wg-easy для её внутреннего API;
- отдельные логин, пароль и TOTP secret администратора портала, а также длинный `PORTAL_SESSION_SECRET`.

Сгенерировать session secret можно командой `openssl rand -hex 32`, а TOTP secret — `python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode())'`. TOTP secret добавляется в 2FAS/Google Authenticator как новый ключ. `.env` исключён из Git.

## Первый запуск

1. Завершите мастер wg-easy на `https://VPN_DOMAIN`. В интерфейсе задайте порт клиента `443`, DNS `10.42.42.44` и параметры AmneziaWG.
2. Заполните учётные данные wg-easy в `.env` и повторно запустите `scripts/deploy.sh`.
3. Настройте AdGuard через SSH-туннель `ssh -L 3000:127.0.0.1:3000 root@SERVER`. DNS должен слушать `0.0.0.0:53`; upstream: `10.42.42.1:5353`, `:5354`, `:5355`, `:5356`, режим `parallel`, timeout `5s`.
4. Откройте `https://PORTAL_DOMAIN/admin/login`, авторизуйтесь логином, паролем и TOTP из `PORTAL_ADMIN_*`, затем добавьте разрешённые телефоны с лимитами.

Постбек Zvonok не требуется: портал регистрирует проверку и опрашивает результат через официальный API. После первого реального теста при необходимости поправьте `ZVONOK_SUCCESS_STATUSES` по значению `call_status` вашей кампании.

## Российский выход

Положите рабочий конфиг второго сервера в `/etc/wireguard/wg-ru.conf` по примеру [examples/wg-ru.conf.example](examples/wg-ru.conf.example), поднимите `wg-quick up wg-ru` и включите unit `wg-quick@wg-ru`. В `config/sing-box.json` укажите реальные имена внешнего интерфейса и `wg-ru`.

Сейчас через РФ направляются `.ru`, `.рф`, Yandex, 2GIS и перечисленные проектом исключения. Список `domain_suffix` можно менять перед развёртыванием. Остальной трафик идёт через основной VPS. DNS-запросы клиентов принимает только AdGuard, далее они уходят через четыре DoH upstream.

## Безопасность и данные

Ключ Zvonok, пароль/TOTP панели, телефонные номера и конфиги никогда не коммитятся. Телефоны и связи устройств находятся в volume `portal_data`; ключи клиентов остаются в volume wg-easy. Пользователь видит только собственные устройства. Сессия выдаётся лишь после звонка с номера из белого списка.

## Проверка и управление

```bash
./scripts/validate.sh
docker compose ps
curl -fsS https://YOUR_PORTAL/healthz
journalctl -u aas-vpn-watchdog --since today
```

Повторный запуск deploy обновляет образы и код, не удаляя volumes и существующих клиентов.
