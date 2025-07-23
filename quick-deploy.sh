#!/bin/bash

set -e

echo "🚀 Deploying RWTS acme-dns service from GitHub"

# Detect public IP
PUBLIC_IP=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org)
echo "📍 Detected public IP: $PUBLIC_IP"

# Clone the repository
if [ -d "acmedns" ]; then
    echo "📂 Updating existing repository..."
    cd acmedns
    git pull
else
    echo "📂 Cloning repository..."
    git clone https://github.com/realworldtech/acmedns.git
    cd acmedns
fi

# Make scripts executable
chmod +x *.sh

# Install Docker if needed
if ! command -v docker &> /dev/null; then
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker $USER
    echo "⚠️  You may need to log out and back in for Docker permissions"
fi

# Check if Docker Compose plugin is available
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose plugin not available. Please update Docker to a recent version."
    echo "   Alternatively, you can install docker-compose separately:"
    echo "   curl -L \"https://github.com/docker/compose/releases/latest/download/docker-compose-\$(uname -s)-\$(uname -m)\" -o /usr/local/bin/docker-compose"
    echo "   chmod +x /usr/local/bin/docker-compose"
    exit 1
fi

# Generate master API key if it doesn't exist
if [ ! -f "master.key" ]; then
    MASTER_KEY="master_$(openssl rand -hex 32)"
    echo "🔑 Generated master API key: $MASTER_KEY"
    echo "$MASTER_KEY" > master.key
    chmod 600 master.key
else
    echo "🔑 Using existing master key"
    MASTER_KEY=$(cat master.key)
fi

# Update acme-dns config with actual IP
sed -i "s/\${PUBLIC_IP}/$PUBLIC_IP/g" acme-dns/config.cfg

# Generate secure passwords for dashboards
echo "🔐 Generating secure dashboard passwords..."
DASHBOARD_PASS=$(openssl rand -base64 12)
ADMIN_PASS=$(openssl rand -base64 12)

DASHBOARD_HASH=$(docker run --rm httpd:2.4-alpine htpasswd -nbB admin "$DASHBOARD_PASS" | cut -d: -f2)
ADMIN_HASH=$(docker run --rm httpd:2.4-alpine htpasswd -nbB admin "$ADMIN_PASS" | cut -d: -f2)

# Create/update environment file
cat > .env << EOF
# Master API key for management
MASTER_API_KEY=$MASTER_KEY

# Public IP
PUBLIC_IP=$PUBLIC_IP

# Dashboard authentication (auto-generated)
DASHBOARD_AUTH=admin:$DASHBOARD_HASH
ADMIN_AUTH=admin:$ADMIN_HASH
EOF

# Save passwords to file for reference
cat > dashboard-credentials.txt << EOF
Dashboard Credentials (keep secure!)
=====================================

Traefik Dashboard: https://traefik.acmedns.realworld.net.au
Username: admin
Password: $DASHBOARD_PASS

Admin Dashboard: https://admin.acmedns.realworld.net.au  
Username: admin
Password: $ADMIN_PASS

Generated: $(date)
EOF

chmod 600 dashboard-credentials.txt

# Set up firewall
echo "🔥 Configuring firewall..."
ufw allow 22/tcp    # SSH
ufw allow 53/tcp    # DNS
ufw allow 53/udp    # DNS
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw --force enable || true

# Create systemd service
cat > /etc/systemd/system/acmedns.service << EOF
[Unit]
Description=RWTS acme-dns Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo ""
echo "✅ Deployment setup complete!"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. 🌐 Configure DNS records:"
echo "   acmedns.realworld.net.au.    A      $PUBLIC_IP"
echo "   acmedns.realworld.net.au.    NS     acmedns.realworld.net.au."
echo ""
echo "2. 🚀 Start services:"
echo "   docker compose up -d"
echo "   # OR"
echo "   systemctl enable --now acmedns"
echo ""
echo "3. 🔑 Create your first API key:"
echo "   ./manage-keys.sh create"
echo ""
echo "4. 🧪 Test the service:"
echo "   ./manage-keys.sh test"
echo ""
echo "📊 Service endpoints:"
echo "   API: https://acmedns.realworld.net.au"
echo "   Admin: https://admin.acmedns.realworld.net.au"
echo "   Traefik: https://traefik.acmedns.realworld.net.au"
echo ""
echo "🔐 Dashboard credentials:"
echo "   Traefik Dashboard:"
echo "     URL: https://traefik.acmedns.realworld.net.au"
echo "     Username: admin"
echo "     Password: $DASHBOARD_PASS"
echo ""
echo "   Admin Dashboard:"
echo "     URL: https://admin.acmedns.realworld.net.au"
echo "     Username: admin" 
echo "     Password: $ADMIN_PASS"
echo ""
echo "   💾 Credentials saved to: dashboard-credentials.txt"
echo ""
echo "🔑 Master API key saved to: master.key"
echo "   Keep this secure and backed up!"
echo ""
echo "📚 Usage example for martens.com.au:"
echo "   # Get API key first:"
echo "   ./manage-keys.sh create"
echo ""
echo "   # Register domain:"
echo "   curl -X POST https://acmedns.realworld.net.au/register \\"
echo "     -H 'X-API-Key: your-api-key' \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"domain\": \"marpve01.infrastructure.martens.com.au\"}'"
echo ""
echo "   # Add CNAME in martens.com.au DNS:"
echo "   _acme-challenge.marpve01.infrastructure.martens.com.au. CNAME [uuid].acmedns.realworld.net.au."
echo ""
echo "   # Configure Proxmox ACME plugin with:"
echo "   URL: https://acmedns.realworld.net.au/update"
echo "   API Key: your-api-key"
echo ""