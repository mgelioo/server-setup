#!/bin/bash

# This script automates the setup of Xray with Nginx (HTTP/3 + QUIC)
# and installs a user management script for Xray on Ubuntu 22.04.

# --- Global Variables ---
XRAY_CONFIG_PATH="/usr/local/etc/xray/config.json"
XRAY_USER_DB_PATH="/usr/local/etc/xray/user_database.txt"
NGINX_CONF_PATH="/etc/nginx/nginx.conf"
NGINX_SERVICE_PATH="/etc/systemd/system/nginx.service"
XRAY_MANAGER_SCRIPT_PATH="/usr/local/bin/xray-manager"
XRAY_LOG_DIR="/var/log/xray"
NGINX_LOG_DIR="/usr/local/nginx/logs"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi;
echo "--- Starting full server setup ---"

# --- Step 1: Update system ---
echo "## Step 1: Updating system packages..."
apt update -y || { echo "Error: apt update failed."; exit 1; };
apt upgrade -y || { echo "Warning: apt upgrade failed, continuing..."; }
echo "System update complete."
echo "----------------------------------------"

# --- Step 2: Install Xray in /root and configure ---
echo "## Step 2: Installing Xray..."
# Ensure we are in /root before running the Xray install script
cd /root || { echo "Error: Could not change to /root directory."; exit 1; }
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || { echo "Error: Xray installation failed."; exit 1; }
echo "Xray installed."

echo "## Step 2.1: Configuring Xray with provided config.json..."
# Create Xray log directory if it doesn't exist
mkdir -p "$XRAY_LOG_DIR" || { echo "Error: Could not create Xray log directory."; exit 1; }

# Xray config - Using 'EOF' with quotes to prevent variable expansion inside
cat > "$XRAY_CONFIG_PATH" << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 2000,
      "protocol": "vless",
      "settings": {
        "clients": [

        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/xhttp7970"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      }
    ]
  },
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}
EOF
echo "Xray configuration updated."
echo "----------------------------------------"

# --- Step 3: Clone quictls/openssl and install build dependencies ---
echo "## Step 3: Cloning quictls/openssl..."
git clone --depth 1 -b openssl-3.3.0-quic1 https://github.com/quictls/openssl.git quictls || { echo "Error: Cloning quictls/openssl failed."; exit 1; }
echo "quictls/openssl cloned to /root/quictls."
echo "----------------------------------------"

echo "## Step 4: Installing Nginx build dependencies and downloading Nginx..."
apt-get install -y gcc g++ libpcre3 libpcre3-dev zlib1g zlib1g-dev openssl libssl-dev wget sudo make curl socat cron jq uuid-runtime bc qrencode || { echo "Error: Installing Nginx dependencies failed."; exit 1; }
echo "Nginx build dependencies installed."

echo "Downloading Nginx source..."
wget https://nginx.org/download/nginx-1.27.3.tar.gz || { echo "Error: Nginx download failed."; exit 1; }
echo "Extracting Nginx source..."
tar -xvf nginx-1.27.3.tar.gz || { echo "Error: Nginx extraction failed."; exit 1; }
echo "Nginx source extracted to /root/nginx-1.27.3."
echo "----------------------------------------"

# --- Step 5: Configure, compile, and install Nginx ---
echo "## Step 5: Configuring, compiling, and installing Nginx..."
cd /root/nginx-1.27.3 || { echo "Error: Could not change to Nginx source directory."; exit 1; }

echo "Running Nginx configure script..."
./configure \
  --prefix=/usr/local/nginx \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --with-http_stub_status_module \
  --with-http_ssl_module \
  --with-http_realip_module \
  --with-http_sub_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-http_v2_module \
  --with-http_v3_module \
  --with-openssl=../quictls \
  --with-cc-opt="-I/opt/quictls/include" \
  --with-ld-opt="-L/opt/quictls/lib " || { echo "Error: Nginx configure failed."; exit 1; }
echo "Nginx configure complete."

echo "Compiling Nginx (this may take a while)..."
make || { echo "Error: Nginx compilation failed."; exit 1; }
echo "Nginx compilation complete."

echo "Installing Nginx..."
make install || { echo "Error: Nginx installation failed."; exit 1; }
echo "Nginx installed to /usr/local/nginx."
echo "----------------------------------------"

# --- Step 6: Configure Nginx ---
echo "## Step 6: Configuring Nginx with user inputs..."

read -p "Enter your Nginx server name (e.g., farhad.marfanet.com): " SERVER_NAME
if [ -z "$SERVER_NAME" ]; then
    echo "Server name cannot be empty. Aborting Nginx configuration."
    exit 1
fi

read -p "Enter the FULL path to your SSL certificate file (e.g., /etc/ssl/certs/mycert.pem): " SSL_CERT_PATH
if [ -z "$SSL_CERT_PATH" ]; then
    echo "SSL certificate path cannot be empty. Aborting Nginx configuration."
    exit 1
fi

read -p "Enter the FULL path to your SSL certificate KEY file (e.g., /etc/ssl/private/mykey.key): " SSL_KEY_PATH
if [ -z "$SSL_KEY_PATH" ]; then
    echo "SSL key path cannot be empty. Aborting Nginx configuration."
    exit 1
fi

# Create Nginx log directory if it doesn't exist
mkdir -p "$NGINX_LOG_DIR" || { echo "Error: Could not create Nginx log directory."; exit 1; }

# Generate Nginx config with user inputs - Variables are expanded here
cat > "$NGINX_CONF_PATH" << EOF
# WARNING: Running worker processes as root is a major security risk!
user root;

# Automatically set the number of worker processes based on CPU cores
worker_processes auto;

# Error log location and level (as requested)
error_log /usr/local/nginx/logs/error.log notice; # Ensure this directory exists

# PID file location
pid /run/nginx.pid; # Standard location, adjust if your build uses a different default

events {
    # Max connections per worker process
    worker_connections 1024;
    # Accept multiple connections at once
    multi_accept on;
}

http {
    # ---- Basic HTTP Settings ----
    include         /etc/nginx/mime.types; # Ensure this path is correct for your setup
    default_type    application/octet-stream;

    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off; # Hide Nginx version
# Define the 'main' log format (as requested)
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                     '\$status \$body_bytes_sent "\$http_referer" '
                     '"\$http_user_agent" "\$http_x_forwarded_for"';

    # Access log location and format (as requested)
    access_log /usr/local/nginx/logs/access.log main; # Ensure this directory exists

    # Enable Gzip compression (optional but recommended)
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;

    # ---- Global SSL/TLS Settings ----
    ssl_protocols TLSv1.2 TLSv1.3; # Require TLS 1.3 for HTTP/3
    ssl_prefer_server_ciphers on;
    # Modern cipher suite (adjust based on compatibility needs)
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m; # 10 megabytes shared cache
    ssl_session_timeout 10m;
    ssl_session_tickets off; # Recommended for Perfect Forward Secrecy

    # OCSP Stapling (Improves TLS handshake speed and privacy)
    ssl_stapling on;
    ssl_stapling_verify on;
    # IMPORTANT: Your trusted certificate chain
    ssl_trusted_certificate ${SSL_CERT_PATH};
# Provide DNS resolvers for OCSP lookup (e.g., Google's or your local ones)
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # ---- Server Block for HTTP (Redirect to HTTPS) ----
    server {
        listen 80;
        listen [::]:80;
        server_name ${SERVER_NAME};

        location / {
            # Permanent redirect to HTTPS
            return 301 https://\$host\$request_uri;
        }
    }

    # ---- Server Block for HTTPS (HTTP/2 & HTTP/3) and gRPC ----
    server {
        # Listen on TCP 443 for HTTPS (HTTP/1.1 and HTTP/2)
        listen 443 ssl http2;
        listen [::]:443 ssl http2;

        # Listen on UDP 443 for HTTP/3 (QUIC)
        # reuseport is recommended for performance with multiple workers
        listen 443 quic reuseport;
        listen [::]:443 quic reuseport;

        server_name ${SERVER_NAME};

        # ---- SSL Certificate Configuration ----
        ssl_certificate ${SSL_CERT_PATH};
        ssl_certificate_key ${SSL_KEY_PATH};

# ---- HTTP/3 Specific Settings ----
        # Advertise HTTP/3 support to browsers via Alt-Svc header
        add_header Alt-Svc 'h3=":443"; ma=86400'; # ma = max-age in seconds (e.g., 24 hours)
        # Enable 0-RTT data for QUIC (improves performance for returning visitors)
        ssl_early_data on;

        # ---- Security Headers (Recommended) ----
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# ---- Location Block for gRPC ----
        location /xhttp7970 {
            grpc_pass grpc://127.0.0.1:2000;

            # Forward client information (optional but often useful)
            grpc_set_header Host \$host;
            grpc_set_header X-Real-IP \$remote_addr;
            grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            grpc_set_header X-Forwarded-Proto \$scheme;

            # Increase timeouts for potentially long-running gRPC streams (adjust as needed)
            grpc_read_timeout 300s;
            grpc_send_timeout 300s;
        }
    }
}
EOF
echo "Nginx configuration updated based on your input."
echo "----------------------------------------"

# --- Step 7: Nginx Systemd Service and start ---
echo "## Step 7: Setting up Nginx Systemd service and starting Nginx..."

# Nginx Service file - Using 'EOF' with quotes to prevent variable expansion inside
cat > "$NGINX_SERVICE_PATH" << 'EOF'
[Unit]
Description=A high performance web server and a reverse proxy server
Documentation=man:nginx(8)
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
echo "Nginx systemd service file created."

echo "Testing Nginx configuration..."
/usr/sbin/nginx -t || { echo "Error: Nginx configuration test failed. Please check /etc/nginx/nginx.conf for errors."; exit 1; }
echo "Nginx configuration test successful."

echo "Reloading systemd daemon..."
systemctl daemon-reload || { echo "Error: systemctl daemon-reload failed."; exit 1; }

echo "Enabling Nginx service..."
systemctl enable nginx.service || { echo "Error: systemctl enable nginx.service failed."; exit 1; }

echo "Restarting Nginx service..."
systemctl restart nginx || { echo "Error: systemctl restart nginx failed. Check Nginx error logs for details."; exit 1; }

echo "Checking Nginx service status..."
systemctl status nginx --no-pager || { echo "Warning: Nginx service status check failed. Please manually check 'systemctl status nginx'."; }
echo "Nginx service setup complete."
echo "----------------------------------------"

# --- Step 8: Install Xray User Manager script ---
echo "## Step 8: Installing Xray User Manager script..."

# Ensure the user database file exists
touch "$XRAY_USER_DB_PATH" || { echo "Error: Could not create user database file."; exit 1; }

# Write the Xray manager script - Using 'SCRIPTEOF' with quotes to prevent expansion
cat > "$XRAY_MANAGER_SCRIPT_PATH" << 'SCRIPTEOF'
#!/bin/bash

# This script manages VLESS users for Xray, including adding, listing,
# activating/deactivating, generating QR codes, and enforcing limits.


# --- Configuration ---
# Path to your Xray configuration file
XRAY_CONFIG="/usr/local/etc/xray/config.json"
# Path to the database file storing user UUIDs, names, expiration, and traffic limits
USER_DB="/usr/local/etc/xray/user_database.txt"
# The 'tag' of the VLESS inbound section in your Xray config.json that this script manages.
# This must exactly match a "tag" field within an "inbounds" block in your Xray config.
INBOUND_TAG="vless-in" # Default, adjust if your inbound tag is different.


# --- QR CODE CONFIGURATION (IMPORTANT: EDIT THESE BASED ON YOUR SERVER'S PUBLIC DETAILS!) ---
# This is the public IP address clients will connect to directly.
# SERVER_ADDRESS="104.17.148.22" # This will be derived from your Nginx server_name
# Automatically get server IP. Note: This might return internal IP if behind NAT.
# It's safer to manually set SERVER_ADDRESS if you have a specific public IP.
# Public IP lookup (can vary based on external service reliability)
# SERVER_ADDRESS=$(curl -s ifconfig.me) # Use an external service
# Or, if you know your public IP:
SERVER_ADDRESS="$(hostname -I | awk '{print $1}')" # Tries to get primary IP, may be local.
if [[ -z "$SERVER_ADDRESS" || "$SERVER_ADDRESS" == "127.0.0.1" ]]; then
    echo "Warning: Could not automatically determine public IP. Please set SERVER_ADDRESS manually in the script."
    echo "Falling back to placeholder 104.17.148.22. Edit $XRAY_MANAGER_SCRIPT_PATH to correct."
    SERVER_ADDRESS="104.17.148.22"
fi

# This is the domain name used for TLS SNI (Server Name Indication) and HTTP Host headers.
# This should match the domain on your TLS certificate and Nginx configuration.
# DOMAIN_FOR_HOST_SNI="farhad.marfanet.com" # This will be derived from your Nginx config
DOMAIN_FOR_HOST_SNI=$(grep 'server_name' /etc/nginx/nginx.conf | awk '{print $2}' | tr -d ';' | head -n 1)
if [ -z "$DOMAIN_FOR_HOST_SNI" ]; then
    echo "Warning: Could not automatically determine DOMAIN_FOR_HOST_SNI from Nginx config."
    echo "Falling back to placeholder farhad.marfanet.com. Edit $XRAY_MANAGER_SCRIPT_PATH to correct."
    DOMAIN_FOR_HOST_SNI="farhad.marfanet.com"
fi


# The public port Nginx listens on, which forwards to Xray. (Typically 443 for HTTPS)
PUBLIC_PORT="443"

# The specific path configured in your Xray streamSettings.xhttpSettings.path
# This must exactly match the path in your Xray server configuration.
VLESS_PATH="/xhttp7970"
# ---------------------------------------------------------------------------------


# Pre-encode VLESS_PATH for URI. Requires 'jq'. This ensures the path is URL-safe.
VLESS_PATH_ENCODED=$(printf %s "${VLESS_PATH}" | jq -sRr @uri)

# Global associative array to store all user traffic stats.
# This is populated once to speed up operations like 'list_users'. Requires Bash 4.0+.
declare -g -A ALL_USER_TRAFFIC_STATS


# --- Helper Functions ---

# Restarts the Xray service. Called after making changes to Xray config.
function restart_xray {
    echo "Restarting Xray service..."
    systemctl restart xray
    if [ $? -eq 0 ]; then
        echo "Xray service restarted successfully."
    else
        echo "Error: Xray service restart failed. Check logs."
    fi
}

# --- Traffic Statistics Optimization ---

# Fetches all user traffic statistics from Xray's API in a single query
# and populates the global ALL_USER_TRAFFIC_STATS array.
function get_all_user_traffic_stats {
    echo "Fetching all user traffic statistics from Xray..."

    # Reset the associative array before populating to ensure fresh data
    unset ALL_USER_TRAFFIC_STATS
    declare -g -A ALL_USER_TRAFFIC_STATS

    # Query Xray API for all user traffic stats. Redirect stderr to /dev/null to suppress errors.
    local raw_stats=$(/usr/local/bin/xray api statsquery --server=127.0.0.1:10085 -pattern "user>>>.*>>>traffic.*" -reset=false 2>/dev/null)

    # Use awk to parse the raw stats. It splits lines by '>' or ':' and sums uplink/downlink per user.
    echo "$raw_stats" | awk -F'[>:]' '
        /^user/{ # Only process lines that start with "user"
            user=$2;  # Extracts the email/name (e.g., "testuser1")
            type=$4;  # Extracts "uplink" or "downlink"
            bytes=$5; # Extracts the bytes string (e.g., " 12345")
            gsub(/ /, "", bytes); # Remove leading space from the bytes string

            if (type == "uplink") {
                uplink_bytes[user] += bytes;
            } else if (type == "downlink") {
                downlink_bytes[user] += bytes;
            }
        }
        END { # After processing all lines, print the total for each user
            for (user in uplink_bytes) {
                print user, (uplink_bytes[user] + downlink_bytes[user]);
            }
            # Also include users who might only have downlink stats (e.g., if uplink is 0)
            for (user in downlink_bytes) {
                if (!(user in uplink_bytes)) { # If user only has downlink stats (no uplink yet)
                    print user, downlink_bytes[user];
                }
            }
        }
    ' | while IFS=$' ' read -r username total_bytes; do
        # Populate the global associative array
        ALL_USER_TRAFFIC_STATS["$username"]="$total_bytes"
    done
    echo "Traffic statistics fetch complete."
}


# --- QR CODE & URI FUNCTIONS ---

# Generates a VLESS URI based on provided user details and global config.
# Parameters: $1 = UUID, $2 = Client Name (email)
function generate_vless_uri {
    local uuid=$1
    local name=$2
    local uri=""

    # Encode the client name for the URI's remark field (e.g., spaces to %20).
    local remark_encoded=$(printf %s "$name" | jq -sRr @uri)

    # Construct the VLESS URI with all specified parameters.
    # The 'type=xhttp' is used as confirmed by your working client URL.
    uri="vless://${uuid}@${SERVER_ADDRESS}:${PUBLIC_PORT}?mode=auto&path=${VLESS_PATH_ENCODED}&security=tls&alpn=h2&encryption=none&host=${DOMAIN_FOR_HOST_SNI}&fp=chrome&type=xhttp&sni=${DOMAIN_FOR_HOST_SNI}#${remark_encoded}"
    echo "$uri"
}

# Displays the VLESS URI and generates a QR code in the terminal if qrencode is installed.
# Parameter: $1 = VLESS URI string
function display_qr_code {
    local uri=$1

    echo "----------------------------------------"
    echo "VLESS Configuration Link:"
    echo "$uri"
    echo "----------------------------------------"

    # Check if qrencode command is available
    if command -v qrencode &> /dev/null; then
        echo "QR Code for scanning (requires UTF-8 terminal support):"
        qrencode -t UTF8 "$uri" # Generates a QR code readable in UTF-8 terminals
    else
        echo "Warning: 'qrencode' is not installed. Cannot display QR code in terminal."
        echo "Please install it using: sudo apt install qrencode (Debian/Ubuntu) or sudo yum install qrencode (CentOS/RHEL)"
    fi
    echo "----------------------------------------"
}


# --- User Management Functions ---

# Adds a new VLESS user to Xray configuration and the user database.
function add_user {
    read -p "Enter client name (no spaces, e.g., user1): " client_name
    if [ -z "$client_name" ]; then
        echo "Client name cannot be empty. Aborting."
        return
    fi
    # Validate client_name: alphanumeric and underscores only, no spaces.
    if [[ "$client_name" =~ [[:space:]] || ! "$client_name" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "Invalid client name. Please use alphanumeric characters and underscores only, no spaces."
        return
    fi

    # Check if client name already exists in the user database.
    if grep -q ";$client_name;" "$USER_DB"; then
        echo "Error: User with name '$client_name' already exists. Please choose a different name."
        return
    fi

    read -p "Enter usage duration in days (e.g., 30): " duration_days
    if ! [[ "$duration_days" =~ ^[0-9]+$ ]] || [ "$duration_days" -le 0 ]; then
        echo "Invalid duration. Please enter a positive number of days."
        return
    fi

    read -p "Enter traffic limit in GB (e.g., 20, use 0 for unlimited): " traffic_limit_gb
    if ! [[ "$traffic_limit_gb" =~ ^[0-9]+$ ]] || [ "$traffic_limit_gb" -lt 0 ]; then
        echo "Invalid traffic limit. Please enter a non-negative number."
        return
    fi

    # Generate a new UUID for the user. Requires 'uuid-runtime' package (for uuidgen).
    new_uuid=$(uuidgen)

    # Calculate expiration date as a Unix timestamp (seconds since epoch).
    expiration_timestamp=$(date -d "+$duration_days days" +%s)

    echo "----------------------------------------"
    echo "Adding new user details:"
    echo "  Name: $client_name"
    echo "  UUID: $new_uuid"
    echo "  Expires on: $(date -d @$expiration_timestamp)"
    echo "  Traffic Limit: ${traffic_limit_gb}GB"
    echo "----------------------------------------"

    # Append user data to the database file.
    echo "$new_uuid;$client_name;$expiration_timestamp;$traffic_limit_gb;active" | sudo tee -a "$USER_DB" > /dev/null

    # Add user to Xray config.json using jq.
    # First, check if the specified inbound tag exists in the Xray config.
    if ! sudo jq -e '.inbounds[] | select(.tag == "'"$INBOUND_TAG"'")' "$XRAY_CONFIG" > /dev/null; then
        echo "Error: Inbound with tag '$INBOUND_TAG' not found in Xray config. Please check your config.json."
        # If inbound is not found, remove the user from the database as Xray won't use them.
        sudo sed -i "/^$new_uuid;/d" "$USER_DB"
        return
    fi

    # Use jq to append a new client entry to the specified inbound's clients array.
    sudo jq --arg uuid "$new_uuid" --arg email "$client_name" \
        '(.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients) |= . + [{"id": $uuid, "email": $email, "flow": ""}]' \
        "$XRAY_CONFIG" > tmp.json && sudo mv tmp.json "$XRAY_CONFIG"

    if [ $? -eq 0 ]; then
        echo "User '$client_name' added successfully to Xray config."
        restart_xray # Restart Xray to apply config changes.
        # Generate and display QR code for the new user.
        local vless_uri=$(generate_vless_uri "$new_uuid" "$client_name")
        display_qr_code "$vless_uri"
    else
        echo "Error: Failed to add user to Xray config."
        # If Xray config update fails, remove the user from the database to keep consistency.
        sudo sed -i "/^$new_uuid;/d" "$USER_DB"
    fi
}

# ---
## Function to delete an existing user
# ---
function delete_user {
    echo "Listing all users..."
    list_users # Show current users for selection
    read -p "Enter the **UUID** of the user you want to DELETE permanently: " user_uuid_to_delete

    if [ -z "$user_uuid_to_delete" ]; then
        echo "No UUID entered. Aborting deletion."
        return
    fi

    # Retrieve user record from the database.
    user_record=$(grep "^$user_uuid_to_delete;" "$USER_DB")
    if [ -z "$user_record" ]; then
        echo "Error: User with UUID $user_uuid_to_delete not found in database. Nothing to delete."
        return
    fi

    local client_name=$(echo "$user_record" | cut -d';' -f2)

    echo "----------------------------------------"
    echo "WARNING: You are about to permanently delete user '$client_name' (UUID: $user_uuid_to_delete)."
    read -p "Are you sure you want to proceed? (yes/no): " confirm_delete
    echo "----------------------------------------"

    if [[ "$confirm_delete" != "yes" ]]; then
        echo "Deletion aborted by user."
        return
    fi

    echo "Proceeding with deletion of user '$client_name' (UUID: $user_uuid_to_delete)..."

    # 1. Remove user from Xray config.json
    # Check if the inbound exists before attempting to modify.
    if ! sudo jq -e '.inbounds[] | select(.tag == "'"$INBOUND_TAG"'")' "$XRAY_CONFIG" > /dev/null; then
        echo "Warning: Inbound with tag '$INBOUND_TAG' not found in Xray config. User cannot be removed from config."
    else
        # Use jq to filter out the client with the specified UUID.
        sudo jq '(.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients) |= map(select(.id != "'"$user_uuid_to_delete"'"))' \
            "$XRAY_CONFIG" > tmp.json && sudo mv tmp.json "$XRAY_CONFIG"
        if [ $? -eq 0 ]; then
            echo "User '$client_name' removed from Xray config."
        else
            echo "Error: Failed to remove user '$client_name' from Xray config."
            echo "Manual intervention might be needed to clean up $XRAY_CONFIG."
        fi
    fi

    # 2. Remove user from the database file
    local temp_db=$(mktemp)
    grep -v "^$user_uuid_to_delete;" "$USER_DB" | sudo tee "$temp_db" > /dev/null
    sudo mv "$temp_db" "$USER_DB"

    if grep -q "^$user_uuid_to_delete;" "$USER_DB"; then
        echo "Error: Failed to remove user '$client_name' from database."
    else
        echo "User '$client_name' removed from database."
    fi

    restart_xray # Restart Xray to apply config changes.
    echo "User '$client_name' has been permanently deleted."
}


# Deactivates a user by removing them from Xray config and updating their status in the database.
function deactivate_user {
    echo "Listing all users..."
    list_users # Show current users for selection, now faster due to optimization.
    read -p "Enter the UUID of the user you want to DEACTIVATE: " user_uuid


    if [ -z "$user_uuid" ]; then
        echo "No UUID entered. Aborting."
        return
    fi

    # Retrieve user record from the database.
    user_record=$(grep "^$user_uuid;" "$USER_DB")
    if [ -z "$user_record" ]; then
        echo "Error: User with UUID $user_uuid not found in database."
        return
    fi

    local user_status=$(echo "$user_record" | cut -d';' -f5)
    local client_name=$(echo "$user_record" | cut -d';' -f2)

    # Check if the user is already inactive.
    if [ "$user_status" != "active" ]; then
        echo "User '$client_name' is already inactive (Status: $user_status). No action taken."
        return
    fi


    echo "Deactivating user '$client_name' (UUID: $user_uuid)..."


    # 1. Remove user from Xray config.json.
    # Check if the inbound exists before attempting to modify.
    if ! sudo jq -e '.inbounds[] | select(.tag == "'"$INBOUND_TAG"'")' "$XRAY_CONFIG" > /dev/null; then
        echo "Warning: Inbound with tag '$INBOUND_TAG' not found in Xray config. User cannot be removed from config."
    else
        # Use jq to filter out the client with the specified UUID.
        sudo jq '(.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients) |= map(select(.id != "'"$user_uuid"'"))' \
            "$XRAY_CONFIG" > tmp.json && sudo mv tmp.json "$XRAY_CONFIG"
        if [ $? -eq 0 ]; then
            echo "User '$client_name' removed from Xray config."
        else
            echo "Error: Failed to remove user from Xray config."
            # Decide here if you want to abort or continue updating DB despite config failure.
        fi
    fi

    # 2. Update user status in the database to 'deactivated'.
    local temp_db=$(mktemp)
    # Use awk to find the line with the user's UUID and change its status field.
    awk -F';' -v uuid="$user_uuid" 'BEGIN{OFS=";"} {if ($1 == uuid) {$5="deactivated"; print} else {print}}' "$USER_DB" | sudo tee "$temp_db" > /dev/null
    sudo mv "$temp_db" "$USER_DB"

    echo "User has been deactivated in the database."
    restart_xray # Restart Xray to apply config changes.
}


# Activates a user by adding them back to Xray config and updating their status in the database.
function activate_user {
    echo "Listing all users..."
    list_users # Show current users for selection, now faster.
    read -p "Enter the UUID of the user you want to ACTIVATE: " user_uuid

    if [ -z "$user_uuid" ]; then
        echo "No UUID entered. Aborting."
        return
    fi

    # Retrieve user record from the database.
    user_record=$(grep "^$user_uuid;" "$USER_DB")
    if [ -z "$user_record" ]; then
        echo "Error: User with UUID $user_uuid not found in database."
        return
    fi

    local user_status=$(echo "$user_record" | cut -d';' -f5)
    local client_name=$(echo "$user_record" | cut -d';' -f2)
    local user_uuid_from_db=$(echo "$user_record" | cut -d';' -f1) # Ensure we use the UUID from DB for jq.

    # Check if the user is in a state that can be activated.
    if [ "$user_status" != "deactivated" ] && [ "$user_status" != "expired" ] && [ "$user_status" != "over_limit" ]; then
        echo "User '$client_name' is not in a deactivated/expired/over_limit state (Status: $user_status). Cannot activate."
        return
    fi

    echo "Activating user '$client_name' (UUID: $user_uuid)..."

    # 1. Add user back to Xray config.json.
    # Check if the inbound exists.
    if ! sudo jq -e '.inbounds[] | select(.tag == "'"$INBOUND_TAG"'")' "$XRAY_CONFIG" > /dev/null; then
        echo "Warning: Inbound with tag '$INBOUND_TAG' not found in Xray config. User cannot be added to config."
    else
        # Prevent adding duplicate clients to Xray config.
        if sudo jq -e '.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients[] | select(.id == "'"$user_uuid"'")' "$XRAY_CONFIG" > /dev/null; then
            echo "User '$client_name' (UUID: $user_uuid) is already present in Xray config. Skipping config update."
        else
            # Add the client back to the Xray config.
            sudo jq --arg uuid "$user_uuid_from_db" --arg email "$client_name" \
                '(.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients) |= . + [{"id": $uuid, "email": $email, "flow": ""}]' \
                "$XRAY_CONFIG" > tmp.json && sudo mv tmp.json "$XRAY_CONFIG"
            if [ $? -eq 0 ]; then
                echo "User '$client_name' added back to Xray config."
            else
                echo "Error: Failed to add user back to Xray config."
                # Decide here if you want to abort or continue updating DB.
            fi
        fi
    fi

    # 2. Update user status in the database back to 'active'.
    local temp_db=$(mktemp)
    awk -F';' -v uuid="$user_uuid" 'BEGIN{OFS=";"} {if ($1 == uuid) {$5="active"; print} else {print}}' "$USER_DB" | sudo tee "$temp_db" > /dev/null
    sudo mv "$temp_db" "$USER_DB"

    echo "User has been activated in the database."
    restart_xray # Restart Xray to apply config changes.
    # Display QR code after user is activated.
    local vless_uri=$(generate_vless_uri "$user_uuid_from_db" "$client_name")
    display_qr_code "$vless_uri"
}

# Lists all users from the database, showing their status, expiration, and traffic usage.
function list_users {
    echo "--------------------------------------------------------------------------------------------------------------------------------------"
    printf "%-38s %-15s %-25s %-15s %-15s %-15s %-10s\n" "UUID" "Name" "Expires On" "Time Left" "Traffic Limit" "Traffic Used" "Status"
    echo "--------------------------------------------------------------------------------------------------------------------------------------"

    if [ ! -s "$USER_DB" ]; then
        echo "No users found in the database."
        return
    fi

    local current_time=$(date +%s)

    # Optimize: Fetch all user traffic stats once before looping through users.
    get_all_user_traffic_stats

    # Read each user record from the database.
    while IFS=';' read -r uuid name expires_at limit status; do
        local expires_display=$(date -d @$expires_at '+%Y-%m-%d %H:%M:%S')

        # --- Calculate Time Left ---
        local time_left_display=""
        local display_status="$status" # Default display status is the one from DB

        if [[ "$status" == "active" ]]; then
            local remaining_seconds=$((expires_at - current_time))
            if [ "$remaining_seconds" -le 0 ]; then
                time_left_display="Expired"
                display_status="EXPIRED" # Override for active but expired users
            else
                local days=$((remaining_seconds / 86400))
                local hours=$(( (remaining_seconds % 86400) / 3600 ))
                local minutes=$(( (remaining_seconds % 3600) / 60 ))
                if [ "$days" -gt 0 ]; then
                    time_left_display="${days}d ${hours}h"
                elif [ "$hours" -gt 0 ]; then
                    time_left_display="${hours}h ${minutes}m"
                elif [ "$minutes" -gt 0 ]; then
                    time_left_display="${minutes}m"
                else # Less than 1 minute remaining
                    time_left_display="<1m"
                fi
            fi
        else
            time_left_display="N/A" # Not Applicable for inactive users
        fi

        # --- Calculate Traffic Used ---
        local traffic_used_gb_display="N/A"
        local traffic_limit_gb_display="${limit}GB"

        # Retrieve total traffic bytes from the pre-fetched global array
        local total_traffic_bytes=${ALL_USER_TRAFFIC_STATS["$name"]:-0} # Defaults to 0 if no stats for user

        # Only process traffic if stats are available or it's an active/relevant user
        if [[ "$total_traffic_bytes" -gt 0 || "$status" == "active" || "$status" == "expired" || "$status" == "over_limit" ]]; then
            # Convert bytes to GB for display. Requires 'bc'.
            traffic_used_gb_display=$(echo "scale=2; $total_traffic_bytes / 1073741824" | bc)GB

            if [ "$limit" -gt 0 ]; then # If a traffic limit is set (not 0/unlimited)
                local limit_bytes=$((limit * 1073741824))

                if [ "$total_traffic_bytes" -ge "$limit_bytes" ]; then
                    # If active and over limit, update display_status
                    if [[ "$status" == "active" ]]; then
                        display_status="OVER_LIMIT"
                    fi
                fi
            else # Traffic limit is 0 (unlimited)
                traffic_limit_gb_display="UNLIMITED"
            fi
        fi

        # Print formatted user information.
        printf "%-38s %-15s %-25s %-15s %-15s %-15s %-10s\n" \
               "$uuid" "$name" "$expires_display" "$time_left_display" \
               "$traffic_limit_gb_display" "$traffic_used_gb_display" "$display_status"
    done < "$USER_DB" # Loop reads from the user database file.
    echo "--------------------------------------------------------------------------------------------------------------------------------------"
    echo "Note: 'EXPIRED' or 'OVER_LIMIT' status in this list reflects real-time checks, and will be updated in DB by 'Check/Enforce Limits'."
    echo "      Traffic usage requires Xray's statistics API to be active. Traffic is calculated as uplink + downlink."
}


# Checks for expired users and those who exceeded their traffic limits, then deactivates them.
# Can be run periodically (e.g., via cron job).
function check_limits {
    echo "Running periodic check for expired users and traffic limits..."

    local current_time=$(date +%s)
    local temp_db=$(mktemp) # Create a temporary file for database updates.
    local changes_made=false # Flag to indicate if Xray restart is needed.

    # Optimization: Fetch all user traffic stats once for efficiency in this function too.
    get_all_user_traffic_stats

    # Read each user from the database.
    while IFS=';' read -r uuid name expires_at limit status; do
        local client_email="${name}"
        local original_status=$status # Store original status to detect changes.

        local current_user_config_present=false
        # Check if the user's UUID is currently in the Xray config's clients list.
        if sudo jq -e '(.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients[] | select(.id == "'"$uuid"'"))' "$XRAY_CONFIG" > /dev/null; then
            current_user_config_present=true
        fi

        # Only process users that are currently 'active' for expiration/limit checks.
        if [[ "$status" == "active" ]]; then
            # 1. Check for expiration
            if [[ $current_time -gt $expires_at ]]; then
                echo "User '$name' (UUID: $uuid) has expired. Changing status to 'expired'."
                status="expired"
                changes_made=true
            else
                # 2. Check traffic limit (only if not expired)
                # Use pre-fetched stats for faster lookup.
                local total_traffic=${ALL_USER_TRAFFIC_STATS["$name"]:-0} # Defaults to 0 if no stats found.

                local limit_bytes=$((limit * 1073741824)) # Convert GB to Bytes.

                if [ "$limit" -gt 0 ]; then # Only check if a limit is set (limit > 0 GB).
                    echo "User: $name, Traffic Used: $(echo "scale=2; $total_traffic / 1073741824" | bc)GB, Limit: ${limit}GB"
                    if [[ $total_traffic -ge $limit_bytes ]]; then # Check if total traffic is greater than or equal to limit.
                        echo "User '$name' (UUID: $uuid) has exceeded their traffic limit. Changing status to 'over_limit'."
                        status="over_limit"
                        changes_made=true
                    fi
                else
                    echo "User: $name, Traffic Used: $(echo "scale=2; $total_traffic / 1073741824" | bc)GB, Limit: UNLIMITED"
                fi
            fi
        fi

        # Logic to remove users from Xray config if their status changed from active
        # OR if they are already in an inactive state (expired, over_limit, deactivated) but still in config.
        if [[ ("$original_status" == "active" && "$status" != "active") || \
              (("$status" == "expired" || "$status" == "over_limit" || "$status" == "deactivated") && "$current_user_config_present" == "true") ]]; then

            echo "Removing user '$name' (UUID: $uuid) from Xray config due to status change or persistent inactive status."
            sudo jq '(.inbounds[] | select(.tag == "'"$INBOUND_TAG"'").settings.clients) |= map(select(.id != "'"$uuid"'"))' "$XRAY_CONFIG" > tmp.json && sudo mv tmp.json "$XRAY_CONFIG"
            if [ $? -eq 0 ]; then
                echo "User '$name' removed from Xray config successfully."
                changes_made=true
            else
                echo "Error: Failed to remove user '$name' from Xray config."
            fi
        fi

        # Write the (potentially updated) user record to the temporary database file.
        echo "$uuid;$name;$expires_at;$limit;$status" >> "$temp_db"

    done < "$USER_DB" # Loop reads from the user database file.

    # Overwrite the main user database with the updated temporary one.
    sudo mv "$temp_db" "$USER_DB"

    if [ "$changes_made" = true ]; then
        restart_xray # Restart Xray if any config changes were made.
    else
        echo "No changes needed for Xray config."
    fi
}


# Generates and displays a QR code for an existing user.
function generate_qr_for_user {
    echo "Listing all users..."
    list_users # Show current users for selection, now faster.
    read -p "Enter the UUID of the user for whom you want to generate a QR code: " user_uuid

    if [ -z "$user_uuid" ]; then
        echo "No UUID entered. Aborting."
        return
    fi

    # Retrieve the user's record from the database.
    local user_record=$(grep "^$user_uuid;" "$USER_DB")
    if [ -z "$user_record" ]; then
        echo "Error: User with UUID $user_uuid not found in database."
        return
    fi

    local uuid=$(echo "$user_record" | cut -d';' -f1)
    local client_name=$(echo "$user_record" | cut -d';' -f2)

    echo "Generating QR for user '$client_name' (UUID: $uuid)..."
    local vless_uri=$(generate_vless_uri "$uuid" "$client_name")
    display_qr_code "$vless_uri"
}


# --- Argument handling for cron or direct calls ---
# This allows calling specific functions directly from the command line or a cron job.
# Example: sudo /usr/local/bin/xray_manager.sh check_limits
if [ "$1" == "check_limits" ]; then
    check_limits
    exit 0
fi


# --- Main Menu ---
# This is the interactive menu presented when the script is run without arguments.
echo "Xray User Manager"
echo "-----------------"
PS3="Select an option: "
options=("Add User" "Delete User" "List Users" "Deactivate User" "Activate User" "Generate QR for User" "Check/Enforce Limits" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Add User")
            add_user
            ;;
        "Delete User")
            delete_user
            ;;
        "List Users")
            list_users
            ;;
        "Deactivate User")
            deactivate_user
            ;;
        "Activate User")
            activate_user
            ;;
        "Generate QR for User")
            generate_qr_for_user
            ;;
        "Check/Enforce Limits")
            check_limits
            ;;
        "Quit")
            echo "Exiting Xray User Manager. Goodbye!"
            break # Exit the select loop
            ;;
        *) echo "Invalid option \$REPLY";; # Handle invalid input
    esac
    echo # Newline for better readability after each action
done
SCRIPTEOF
chmod +x "$XRAY_MANAGER_SCRIPT_PATH" || { echo "Error: Could not make Xray manager script executable."; exit 1; }
echo "Xray User Manager script saved to $XRAY_MANAGER_SCRIPT_PATH and made executable."
echo "You can now run it by typing: xray-manager"
echo "----------------------------------------"

echo "--- All setup steps completed successfully! ---"
echo "Remember to open ports 80 (TCP) and 443 (TCP/UDP) in your firewall if they are not already open."
echo "You can manage Xray users by simply typing: xray-manager"
