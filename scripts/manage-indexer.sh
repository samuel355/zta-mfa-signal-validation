#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

COMPOSE_FILE="compose/docker-compose.yml"
INDEXER_CONTAINER="zta_indexer"

print_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if we're in the right directory
if [ ! -f "$COMPOSE_FILE" ]; then
    print_error "Run this script from the project root directory"
    exit 1
fi

# Get Docker Compose command
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

case "${1:-help}" in
    "start")
        print_info "Starting indexer service..."
        $COMPOSE_CMD -f "$COMPOSE_FILE" up -d indexer
        print_success "Indexer started"
        ;;

    "stop")
        print_info "Stopping indexer service..."
        $COMPOSE_CMD -f "$COMPOSE_FILE" stop indexer
        print_success "Indexer stopped"
        ;;

    "restart")
        print_info "Restarting indexer service..."
        $COMPOSE_CMD -f "$COMPOSE_FILE" restart indexer
        print_success "Indexer restarted"
        ;;

    "status")
        print_info "Checking indexer status..."
        docker ps | grep "$INDEXER_CONTAINER" || echo "Indexer not running"
        ;;

    "logs")
        lines=${2:-50}
        print_info "Showing last $lines lines of indexer logs..."
        docker logs --tail="$lines" "$INDEXER_CONTAINER"
        ;;

    "follow")
        print_info "Following indexer logs (Press Ctrl+C to stop)..."
        docker logs -f "$INDEXER_CONTAINER"
        ;;

    "index")
        mode=${2:-once}
        param=${3:-24}
        if ! docker ps | grep -q "$INDEXER_CONTAINER"; then
            print_error "Indexer container is not running. Start it first with: $0 start"
            exit 1
        fi
        print_info "Running $mode indexing..."
        docker exec "$INDEXER_CONTAINER" python elasticsearch-indexer.py "$mode" "$param"
        ;;

    "help"|*)
        echo "Elasticsearch Indexer Management"
        echo ""
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  start           Start the indexer service"
        echo "  stop            Stop the indexer service"
        echo "  restart         Restart the indexer service"
        echo "  status          Show indexer status"
        echo "  logs [lines]    Show indexer logs (default: 50 lines)"
        echo "  follow          Follow indexer logs in real-time"
        echo "  index <mode> [param]  Trigger manual indexing"
        echo "                  - once [hours]      Single run (default: 24)"
        echo "                  - historical [days] Historical data (default: 7)"
        echo "  help            Show this help"
        echo ""
        echo "Examples:"
        echo "  $0 start              # Start indexer"
        echo "  $0 logs 100           # Show last 100 log lines"
        echo "  $0 index once 6       # Index last 6 hours"
        echo "  $0 index historical 14 # Index last 14 days"
        ;;
esac
