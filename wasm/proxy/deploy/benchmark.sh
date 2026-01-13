#!/bin/bash
# Benchmark script for comparing direct vs proxy connections
# Usage: ./benchmark.sh <direct_url> <proxy_url> [iterations]
#
# Example:
#   ./benchmark.sh https://tee.example.com:443 wss://proxy.example.com/tunnel 100

set -e

DIRECT_URL="${1:-}"
PROXY_URL="${2:-}"
ITERATIONS="${3:-50}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <direct_url> <proxy_url> [iterations]"
    echo ""
    echo "Arguments:"
    echo "  direct_url   URL for direct connection (e.g., https://tee.example.com:443)"
    echo "  proxy_url    URL for proxy connection (e.g., wss://proxy.example.com/tunnel)"
    echo "  iterations   Number of test iterations (default: 50)"
    echo ""
    echo "Examples:"
    echo "  $0 https://tee.example.com:443 wss://proxy.example.com/tunnel"
    echo "  $0 https://tee.example.com:443 wss://proxy.example.com/tunnel 100"
    exit 1
}

check_dependencies() {
    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v bc &> /dev/null; then
        missing+=("bc")
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}Missing dependencies: ${missing[*]}${NC}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
}

# Calculate statistics from an array of values
calc_stats() {
    local -n arr=$1
    local sum=0
    local count=${#arr[@]}

    if [ $count -eq 0 ]; then
        echo "0 0 0 0"
        return
    fi

    # Sort the array
    IFS=$'\n' sorted=($(sort -n <<<"${arr[*]}")); unset IFS

    # Calculate sum
    for val in "${arr[@]}"; do
        sum=$(echo "$sum + $val" | bc)
    done

    # Mean
    local mean=$(echo "scale=3; $sum / $count" | bc)

    # Median (p50)
    local mid=$((count / 2))
    local p50=${sorted[$mid]}

    # p95
    local p95_idx=$(echo "scale=0; $count * 95 / 100" | bc)
    local p95=${sorted[$p95_idx]}

    # p99
    local p99_idx=$(echo "scale=0; $count * 99 / 100" | bc)
    local p99=${sorted[$p99_idx]}

    echo "$mean $p50 $p95 $p99"
}

# Measure connection time using curl
measure_connection() {
    local url="$1"
    local result

    # Use curl to measure connection time (in seconds)
    result=$(curl -w "%{time_connect},%{time_appconnect},%{time_total}" \
        -o /dev/null -s --max-time 30 "$url" 2>/dev/null || echo "0,0,0")

    echo "$result"
}

# Measure WebSocket connection time (requires websocat)
measure_websocket() {
    local url="$1"
    local start end elapsed

    if ! command -v websocat &> /dev/null; then
        echo "0"
        return
    fi

    start=$(date +%s%N)
    timeout 5 websocat -1 "$url" </dev/null 2>/dev/null || true
    end=$(date +%s%N)

    elapsed=$(echo "scale=6; ($end - $start) / 1000000000" | bc)
    echo "$elapsed"
}

run_benchmark() {
    echo -e "${YELLOW}Starting benchmark with $ITERATIONS iterations...${NC}"
    echo ""

    local direct_connect=()
    local direct_tls=()
    local direct_total=()
    local proxy_total=()

    echo "Testing direct connection: $DIRECT_URL"
    for i in $(seq 1 $ITERATIONS); do
        printf "\r  Progress: %d/%d" "$i" "$ITERATIONS"

        result=$(measure_connection "$DIRECT_URL")
        IFS=',' read -r connect tls total <<< "$result"

        if [ "$connect" != "0" ]; then
            direct_connect+=("$connect")
            direct_tls+=("$tls")
            direct_total+=("$total")
        fi

        # Small delay to avoid rate limiting
        sleep 0.1
    done
    echo ""

    echo "Testing proxy connection: $PROXY_URL"
    if command -v websocat &> /dev/null; then
        for i in $(seq 1 $ITERATIONS); do
            printf "\r  Progress: %d/%d" "$i" "$ITERATIONS"

            elapsed=$(measure_websocket "$PROXY_URL")
            if [ "$elapsed" != "0" ]; then
                proxy_total+=("$elapsed")
            fi

            sleep 0.1
        done
        echo ""
    else
        echo -e "${YELLOW}  websocat not installed, skipping WebSocket benchmark${NC}"
        echo "  Install with: cargo install websocat"
    fi

    echo ""
    echo -e "${GREEN}=== Results ===${NC}"
    echo ""

    # Direct connection stats
    if [ ${#direct_total[@]} -gt 0 ]; then
        read mean p50 p95 p99 <<< $(calc_stats direct_connect)
        echo "Direct Connection - TCP Connect (seconds):"
        echo "  Mean: ${mean}s | p50: ${p50}s | p95: ${p95}s | p99: ${p99}s"

        read mean p50 p95 p99 <<< $(calc_stats direct_tls)
        echo "Direct Connection - TLS Handshake (seconds):"
        echo "  Mean: ${mean}s | p50: ${p50}s | p95: ${p95}s | p99: ${p99}s"

        read mean p50 p95 p99 <<< $(calc_stats direct_total)
        echo "Direct Connection - Total (seconds):"
        echo "  Mean: ${mean}s | p50: ${p50}s | p95: ${p95}s | p99: ${p99}s"
    else
        echo -e "${RED}Direct connection: No successful measurements${NC}"
    fi

    echo ""

    # Proxy connection stats
    if [ ${#proxy_total[@]} -gt 0 ]; then
        read mean p50 p95 p99 <<< $(calc_stats proxy_total)
        echo "Proxy Connection - Total (seconds):"
        echo "  Mean: ${mean}s | p50: ${p50}s | p95: ${p95}s | p99: ${p99}s"

        # Calculate overhead
        if [ ${#direct_total[@]} -gt 0 ]; then
            direct_mean=$(calc_stats direct_total | cut -d' ' -f1)
            proxy_mean=$mean
            overhead=$(echo "scale=1; ($proxy_mean - $direct_mean) * 1000" | bc)
            pct=$(echo "scale=1; (($proxy_mean - $direct_mean) / $direct_mean) * 100" | bc 2>/dev/null || echo "N/A")
            echo ""
            echo -e "${YELLOW}Proxy overhead: ${overhead}ms (${pct}%)${NC}"
        fi
    else
        echo -e "${YELLOW}Proxy connection: No measurements (websocat required)${NC}"
    fi

    echo ""
    echo "Iterations: $ITERATIONS successful"
}

# Main
if [ -z "$DIRECT_URL" ] || [ -z "$PROXY_URL" ]; then
    usage
fi

check_dependencies
run_benchmark
