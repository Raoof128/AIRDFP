#!/bin/bash
#
# AIRDFP Quick Start Script
# Automated deployment and setup for demonstration purposes
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║   AIRDFP - Automated Incident Response & Digital Forensics   ║"
    echo "║                      Quick Start Setup                        ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3.8+"
        exit 1
    fi
    print_step "Python 3 found: $(python3 --version)"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker"
        exit 1
    fi
    print_step "Docker found: $(docker --version)"

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose"
        exit 1
    fi
    print_step "Docker Compose found: $(docker-compose --version)"

    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker"
        exit 1
    fi
    print_step "Docker daemon is running"

    echo ""
}

setup_python_env() {
    echo -e "${BLUE}Setting up Python environment...${NC}"

    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        print_step "Creating virtual environment..."
        python3 -m venv venv
    else
        print_step "Virtual environment already exists"
    fi

    # Activate virtual environment
    source venv/bin/activate
    print_step "Virtual environment activated"

    # Upgrade pip
    print_step "Upgrading pip..."
    pip install --upgrade pip --quiet

    # Install dependencies
    print_step "Installing Python dependencies..."
    pip install -r requirements.txt --quiet

    echo ""
}

start_docker_services() {
    echo -e "${BLUE}Starting Docker services...${NC}"

    # Stop any existing containers
    print_step "Stopping existing containers (if any)..."
    docker-compose down &> /dev/null || true

    # Start services
    print_step "Starting TheHive, Cortex, and Elasticsearch..."
    docker-compose up -d

    # Wait for services to be ready
    print_step "Waiting for services to initialize (this may take 60-90 seconds)..."
    sleep 60

    # Check Elasticsearch health
    echo -n "Checking Elasticsearch... "
    for i in {1..30}; do
        if curl -s http://localhost:9200/_cluster/health &> /dev/null; then
            echo -e "${GREEN}✓${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}✗${NC}"
            print_warning "Elasticsearch may not be ready yet. Continue anyway."
        fi
        sleep 2
    done

    # Check TheHive
    echo -n "Checking TheHive... "
    for i in {1..30}; do
        if curl -s http://localhost:9000 &> /dev/null; then
            echo -e "${GREEN}✓${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}✗${NC}"
            print_warning "TheHive may not be ready yet. Continue anyway."
        fi
        sleep 2
    done

    echo ""
}

run_validation() {
    echo -e "${BLUE}Running system validation...${NC}"

    # Activate virtual environment
    source venv/bin/activate

    # Run validation script
    python3 tests/validate_system.py

    echo ""
}

print_completion() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║                    🎉 Setup Complete! 🎉                      ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${BLUE}Access Points:${NC}"
    echo "  • TheHive UI:        http://localhost:9000"
    echo "  • Cortex UI:         http://localhost:9001"
    echo "  • Elasticsearch:     http://localhost:9200"
    echo ""

    echo -e "${BLUE}Default Credentials:${NC}"
    echo "  • TheHive:    admin@thehive.local / secret"
    echo "  • Cortex:     admin / thehive1234"
    echo ""

    echo -e "${YELLOW}⚠️  IMPORTANT SECURITY NOTES:${NC}"
    echo "  1. Change default passwords immediately in production"
    echo "  2. Configure SSL/TLS for production deployments"
    echo "  3. Implement firewall rules and network segmentation"
    echo "  4. Rotate API keys every 90 days"
    echo ""

    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Run a demo incident:  python3 scripts/demo_incident.py"
    echo "  2. View documentation:   docs/README.md"
    echo "  3. Configure SIEM:       docs/DEPLOYMENT.md"
    echo ""

    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  • Start services:   docker-compose up -d"
    echo "  • Stop services:    docker-compose down"
    echo "  • View logs:        docker-compose logs -f"
    echo "  • Run tests:        make test"
    echo "  • Run validation:   make validate"
    echo ""
}

# Main execution
main() {
    print_header

    # Check if running from correct directory
    if [ ! -f "docker-compose.yml" ]; then
        print_error "Please run this script from the AIRDFP root directory"
        exit 1
    fi

    # Run setup steps
    check_dependencies
    setup_python_env
    start_docker_services
    run_validation
    print_completion
}

# Run main function
main
