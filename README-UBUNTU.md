# Ubuntu Server Deployment Guide

This folder contains a version of the passkey demo configured to run on Ubuntu.

The original project is left untouched; only files inside this folder are modified.

This version runs **manually** with `start.sh` instead of systemd.

---

## 1. Copy to the server

Copy the contents of this folder to `opt/passkeyapp` on the Ubuntu server.

Do **not** copy the original project's `node_modules/`, `package-lock.json`, or `passkeys.db`.

Example:

```bash
mkdir -p opt/passkeyapp

# Copy files from your local machine to the server
scp -r . user@your-server:opt/passkeyapp
```

---

## 2. Install system dependencies

```bash
sudo apt update
sudo apt install -y build-essential python3 make curl git
```

Install Node.js LTS (e.g., via NodeSource or nvm). Example:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

---

## 3. Configure the environment

```bash
cd opt/passkeyapp
cp .env.example .env
nano .env
```

Set real values:

```ini
RP_ID=yourdomain.duckdns.org
ORIGIN=https://yourdomain.duckdns.org:8443
SESSION_SECRET=...        # openssl rand -hex 32
```

The defaults use port `8443` so the app can run without root. If you want to use port `443`, you must start the app as root.

---

## 4. Point a Duck DNS subdomain to your server

1. Go to https://duckdns.org
2. Create a subdomain, e.g., `yourdomain.duckdns.org`
3. Point it to your Ubuntu server's public IP address
4. Wait a minute for DNS to propagate
5. Verify: `ping yourdomain.duckdns.org`

---

## 5. Run the install script

From the project root:

```bash
cd opt/passkeyapp
sudo bash deploy/install.sh
```

This will:

- Install Node dependencies
- Create `data/` and `certs/` directories
- Obtain a Let's Encrypt certificate for your domain
- Copy the certificate into `certs/`
- Configure UFW firewall rules

---

## 6. Start the app

From the project root:

```bash
./start.sh
```

The app will run in the foreground and print logs. Press `Ctrl+C` to stop.

To stop without Ctrl+C:

```bash
./stop.sh
```

---

## 7. Verify

Open your browser:

```
https://yourdomain.duckdns.org:8443
```

1. Register a new account + passkey.
2. Log out.
3. Log back in.
4. Check the dashboard.

---

## 8. Certificate renewal

Let's Encrypt certificates expire every 90 days. To renew:

```bash
cd opt/passkeyapp
./renew-certs.sh
```

Then restart the app:

```bash
./stop.sh
./start.sh
```

---

## Troubleshooting

### `better-sqlite3` fails to install

Make sure build tools are installed:

```bash
sudo apt install -y build-essential python3 make
```

### App cannot bind to port 443

By default the app uses port `8443` so it does not need root. If you set `PORT=443`, you must start it as root, or bind to a higher port and use a reverse proxy.

### Passkey registration fails

WebAuthn requires a valid domain. It does not work with bare IP addresses. Make sure your Duck DNS subdomain is correctly resolving and the browser shows `https://yourdomain.duckdns.org:8443`.

Also, passkeys registered on `localhost` in the old project will **not** work on the new domain. Users must register new passkeys.

### Certificate permission errors

The install script and `renew-certs.sh` copy the certificate files to `certs/` and set ownership to your user. If they are owned by root, fix it:

```bash
sudo chown $USER:$USER certs/*.pem
chmod 600 certs/*.pem
```

### Port already in use

If `start.sh` says the port is in use, find and stop the existing Node process:

```bash
lsof -i :8443
kill <PID>
```

Then run `./start.sh` again.
