#!/bin/bash

set -e

echo "🚀 Deploying acme-dns service with API key management"

# Detect public IP
PUBLIC_IP=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org)
echo "📍 Detected public IP: $PUBLIC_IP"

# Create directory structure
mkdir -p acmedns-service/{traefik/{dynamic},acme-dns,registration-service,nginx,admin-ui}
cd acmedns-service

# Generate master API key
MASTER_KEY="master_$(openssl rand -hex 32)"
echo "🔑 Generated master API key: $MASTER_KEY"
echo "$MASTER_KEY" > master.key
chmod 600 master.key

# Install Docker and Docker Compose if needed
if ! command -v docker &> /dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker $USER
fi

# Create acme-dns config
cat > acme-dns/config.cfg << EOF
[general]
listen = "0.0.0.0:53"
protocol = "both"
domain = "acmedns.realworld.net.au"
nsname = "acmedns.realworld.net.au"
nsadmin = "admin.realworld.net.au"
records = [
    "acmedns.realworld.net.au. A $PUBLIC_IP",
    "acmedns.realworld.net.au. NS acmedns.realworld.net.au.",
]

[database]
engine = "sqlite3"
connection = "/var/lib/acme-dns/acme-dns.db"

[api]
ip = "0.0.0.0"
port = "8080"
tls = "none"
corsorigins = ["*"]
use_header = true
header_name = "X-Forwarded-For"

[logconfig]
loglevel = "info"
logtype = "stdout"
logformat = "json"
EOF

# Create Traefik config
cat > traefik/traefik.yml << EOF
global:
  checkNewVersion: false
  sendAnonymousUsage: false

api:
  dashboard: true
  insecure: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entrypoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
  dns-udp:
    address: ":53/udp"
  dns-tcp:
    address: ":53/tcp"

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: default
  file:
    directory: /dynamic
    watch: true

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@realworld.net.au
      storage: /certs/acme.json
      httpChallenge:
        entryPoint: web

log:
  level: INFO
  format: json

accessLog:
  format: json
EOF

# Create registration service files
# (Copy the Python files from artifacts)

# Create environment file
cat > .env << EOF
# Master API key for management
MASTER_API_KEY=$MASTER_KEY

# Public IP
PUBLIC_IP=$PUBLIC_IP

# Dashboard authentication (change these!)
DASHBOARD_AUTH=admin:\$2y\$10\$...  # Generate with: htpasswd -nb admin password
ADMIN_AUTH=admin:\$2y\$10\$...      # Generate with: htpasswd -nb admin password
EOF

# Generate auth hashes
echo "🔐 Generating authentication hashes..."
echo -n "Enter dashboard password: "
read -s DASHBOARD_PASS
echo
DASHBOARD_HASH=$(openssl passwd -apr1 "$DASHBOARD_PASS")

echo -n "Enter admin UI password: "
read -s ADMIN_PASS
echo
ADMIN_HASH=$(openssl passwd -apr1 "$ADMIN_PASS")

# Update .env with real hashes
sed -i "s|DASHBOARD_AUTH=.*|DASHBOARD_AUTH=admin:$DASHBOARD_HASH|" .env
sed -i "s|ADMIN_AUTH=.*|ADMIN_AUTH=admin:$ADMIN_HASH|" .env

# Create management script
# (Copy manage-keys.sh from artifacts)
chmod +x manage-keys.sh

# Create systemd service for easy management
cat > /etc/systemd/system/acmedns.service << EOF
[Unit]
Description=acme-dns Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$(pwd)
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Set up firewall
echo "🔥 Configuring firewall..."
ufw allow 22/tcp    # SSH
ufw allow 53/tcp    # DNS
ufw allow 53/udp    # DNS
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw --force enable || true

echo ""
echo "✅ Deployment setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Configure DNS records:"
echo "   acmedns.realworld.net.au.    A      $PUBLIC_IP"
echo "   acmedns.realworld.net.au.    NS     acmedns.realworld.net.au."
echo ""
echo "2. Start services:"
echo "   docker compose up -d"
echo ""
echo "3. Enable service:"
echo "   systemctl enable acmedns"
echo ""
echo "4. Create your first API key:"
echo "   ./manage-keys.sh create"
echo ""
echo "5. Test the service:"
echo "   ./manage-keys.sh test"
echo ""
echo "🔑 Master API key saved to: master.key"
echo "🌐 Service will be available at: https://acmedns.realworld.net.au"
echo "📊 Admin dashboard: https://admin.acmedns.realworld.net.au"
echo "📈 Traefik dashboard: https://traefik.acmedns.realworld.net.au"
echo ""
echo "⚠️  Remember to:"
echo "   - Keep master.key secure and backed up"
echo "   - Configure DNS records before starting services"
echo "   - Change default passwords in .env file"
EOF