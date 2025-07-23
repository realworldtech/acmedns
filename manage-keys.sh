#!/bin/bash

# acme-dns API Key Management Script
# Usage: ./manage-keys.sh <command> [options]

set -e

# Configuration
API_BASE="https://acmedns.realworld.net.au"
MASTER_KEY_FILE="./master.key"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

get_master_key() {
    if [ -f "$MASTER_KEY_FILE" ]; then
        cat "$MASTER_KEY_FILE"
    else
        echo -n "Enter master API key: "
        read -s MASTER_KEY
        echo
        echo "$MASTER_KEY"
    fi
}

api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    
    local master_key=$(get_master_key)
    
    if [ -n "$data" ]; then
        curl -s -X "$method" \
             -H "Authorization: Bearer $master_key" \
             -H "Content-Type: application/json" \
             -d "$data" \
             "$API_BASE$endpoint"
    else
        curl -s -X "$method" \
             -H "Authorization: Bearer $master_key" \
             "$API_BASE$endpoint"
    fi
}

create_key() {
    echo "Create new API key"
    echo -n "Name: "
    read name
    echo -n "Email: "
    read email
    echo -n "Organization: "
    read organization
    echo -n "Expires in days (leave empty for no expiration): "
    read expires_days
    
    local data="{\"name\": \"$name\", \"email\": \"$email\", \"organization\": \"$organization\""
    if [ -n "$expires_days" ]; then
        data="$data, \"expires_days\": $expires_days"
    fi
    data="$data}"
    
    log_info "Creating API key..."
    local response=$(api_call "POST" "/admin/keys" "$data")
    
    if echo "$response" | jq -e '.api_key' > /dev/null 2>&1; then
        log_success "API key created successfully!"
        echo
        echo "Key ID: $(echo "$response" | jq -r '.key_id')"
        echo "API Key: $(echo "$response" | jq -r '.api_key')"
        echo
        log_warning "Store this API key securely - it will not be shown again!"
        
        # Optionally save to file
        echo -n "Save to file? (y/n): "
        read save_file
        if [ "$save_file" = "y" ]; then
            local filename="${name// /_}.key"
            echo "$(echo "$response" | jq -r '.api_key')" > "$filename"
            log_success "API key saved to $filename"
        fi
    else
        log_error "Failed to create API key"
        echo "$response" | jq -r '.error // "Unknown error"'
    fi
}

list_keys() {
    log_info "Fetching API keys..."
    local response=$(api_call "GET" "/admin/keys")
    
    if echo "$response" | jq -e '.[0]' > /dev/null 2>&1; then
        echo
        printf "%-12s %-20s %-30s %-15s %-10s %-8s\n" "KEY ID" "NAME" "ORGANIZATION" "EMAIL" "USAGE" "ACTIVE"
        echo "--------------------------------------------------------------------------------"
        echo "$response" | jq -r '.[] | [.key_id, .name, (.organization // ""), (.email // ""), .usage_count, (.is_active | if . == 1 then "Yes" else "No" end)] | @tsv' | \
        while IFS=$'\t' read -r key_id name org email usage active; do
            printf "%-12s %-20s %-30s %-15s %-10s %-8s\n" "$key_id" "${name:0:20}" "${org:0:30}" "${email:0:15}" "$usage" "$active"
        done
    else
        log_error "Failed to fetch API keys"
        echo "$response" | jq -r '.error // "Unknown error"'
    fi
}

revoke_key() {
    echo -n "Enter key ID to revoke: "
    read key_id
    
    if [ -z "$key_id" ]; then
        log_error "Key ID is required"
        return 1
    fi
    
    log_warning "Are you sure you want to revoke key '$key_id'? (y/n): "
    read confirm
    if [ "$confirm" != "y" ]; then
        log_info "Cancelled"
        return 0
    fi
    
    log_info "Revoking API key..."
    local response=$(api_call "DELETE" "/admin/keys/$key_id")
    
    if echo "$response" | jq -e '.message' > /dev/null 2>&1; then
        log_success "API key revoked successfully"
    else
        log_error "Failed to revoke API key"
        echo "$response" | jq -r '.error // "Unknown error"'
    fi
}

show_stats() {
    log_info "Fetching statistics..."
    local response=$(api_call "GET" "/admin/stats")
    
    if echo "$response" | jq -e '.total_keys' > /dev/null 2>&1; then
        echo
        echo "=== Service Statistics ==="
        echo "Total API Keys: $(echo "$response" | jq -r '.total_keys')"
        echo "Active API Keys: $(echo "$response" | jq -r '.active_keys')"
        echo "Total Registrations: $(echo "$response" | jq -r '.total_registrations')"
        echo "Registrations (24h): $(echo "$response" | jq -r '.registrations_last_24h')"
        echo
        echo "=== Top Users ==="
        printf "%-20s %-30s %-15s\n" "NAME" "ORGANIZATION" "REGISTRATIONS"
        echo "---------------------------------------------------------------"
        echo "$response" | jq -r '.top_users[] | [.name, (.organization // ""), .registration_count] | @tsv' | \
        while IFS=$'\t' read -r name org count; do
            printf "%-20s %-30s %-15s\n" "${name:0:20}" "${org:0:30}" "$count"
        done
    else
        log_error "Failed to fetch statistics"
        echo "$response" | jq -r '.error // "Unknown error"'
    fi
}

list_registrations() {
    log_info "Fetching recent registrations..."
    local response=$(api_call "GET" "/admin/registrations")
    
    if echo "$response" | jq -e '.[0]' > /dev/null 2>&1; then
        echo
        printf "%-20s %-30s %-15s %-20s\n" "KEY NAME" "DOMAIN HINT" "CLIENT IP" "CREATED"
        echo "---------------------------------------------------------------------------------"
        echo "$response" | jq -r '.[] | [.key_name, (.domain_hint // ""), .client_ip, .created_at] | @tsv' | \
        while IFS=$'\t' read -r key_name domain ip created; do
            printf "%-20s %-30s %-15s %-20s\n" "${key_name:0:20}" "${domain:0:30}" "$ip" "${created:0:20}"
        done
    else
        log_error "Failed to fetch registrations"
        echo "$response" | jq -r '.error // "Unknown error"'
    fi
}

test_service() {
    log_info "Testing service health..."
    
    # Test health endpoint
    local health=$(curl -s "$API_BASE/health")
    if echo "$health" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
        log_success "Service is healthy"
    else
        log_error "Service health check failed"
        echo "$health"
        return 1
    fi
    
    # Test master key access
    local stats=$(api_call "GET" "/admin/stats")
    if echo "$stats" | jq -e '.total_keys' > /dev/null 2>&1; then
        log_success "Master key authentication working"
    else
        log_error "Master key authentication failed"
        return 1
    fi
}

show_help() {
    echo "acme-dns API Key Management"
    echo
    echo "Usage: $0 <command>"
    echo
    echo "Commands:"
    echo "  create      Create a new API key"
    echo "  list        List all API keys"
    echo "  revoke      Revoke an API key"
    echo "  stats       Show service statistics"
    echo "  regs        List recent registrations"
    echo "  test        Test service health"
    echo "  help        Show this help"
    echo
    echo "Environment:"
    echo "  MASTER_KEY_FILE  Path to master key file (default: ./master.key)"
    echo
}

# Main script
case "${1:-help}" in
    "create")
        create_key
        ;;
    "list")
        list_keys
        ;;
    "revoke")
        revoke_key
        ;;
    "stats")
        show_stats
        ;;
    "regs")
        list_registrations
        ;;
    "test")
        test_service
        ;;
    "help"|*)
        show_help
        ;;
esac