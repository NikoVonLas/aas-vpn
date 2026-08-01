# AAS VPN

Авторазвёртывание VPN-шлюза на чистом Debian/Ubuntu VPS:

- AmneziaWG через `wg-easy`;
- AdGuard Home для DNS-фильтрации;
- sing-box как прозрачный сетевой слой;
- Caddy с автоматическим HTTPS;
- systemd и watchdog для запуска и восстановления.

## Требования

- VPS с Debian 12+ или Ubuntu 22.04+;
- root-доступ, публичные TCP 80/443 и UDP 443/585;
- A-запись домена, направленная на VPS.

## Установка

```bash
git clone https://github.com/NikoVonLas/aas-vpn.git
cd aas-vpn
cp .env.example .env
nano .env
sudo ./scripts/deploy.sh
```

Установщик можно запускать повторно: он обновляет конфигурацию и образы, не удаляя Docker volumes.

Откройте `https://<VPN_DOMAIN>`, завершите мастер wg-easy и укажите для клиентов:

- Endpoint port: значение `AWG_PORT` (по умолчанию `585`);
- DNS: `10.42.42.44`.

Панель AdGuard намеренно доступна только с localhost сервера. При первом запуске откройте её через туннель:

```bash
ssh -L 3000:127.0.0.1:3000 root@IP_СЕРВЕРА
```

Затем откройте `http://localhost:3000`, выберите прослушивание DNS на всех интерфейсах и upstream `10.42.42.1:5353`. После мастера панель доступна через `ssh -L 3001:127.0.0.1:3001 root@IP_СЕРВЕРА` по адресу `http://localhost:3001`.

## Управление

```bash
systemctl status aas-vpn
docker compose -f /opt/aas-vpn/compose.yml ps
journalctl -u aas-vpn-watchdog --since today
systemctl reload aas-vpn
```

Обновление выполняется повторным запуском `sudo ./scripts/deploy.sh`. Состояние хранится в Docker volumes и не попадает в Git. Файл `.env`, базы, ключи и клиентские конфигурации исключены через `.gitignore`.

## Маршрутизация через второй сервер

Базовая конфигурация выпускает трафик напрямую. Для выборочного выхода через другой сервер добавьте WireGuard-интерфейс на хосте и отдельный outbound/rule в `config/sing-box.json`. Не коммитьте приватный ключ: храните рабочую конфигурацию интерфейса только в `/etc/wireguard`.