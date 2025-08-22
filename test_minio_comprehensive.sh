#!/bin/bash

# Comprehensive MinIO I/O Analysis Test
# Combines eBPF tracer with realistic MinIO workloads

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACER="$SCRIPT_DIR/build/clean_working_categorizer"
WORKLOAD_GENERATOR="$SCRIPT_DIR/minio_workload_generator.sh"
RESULTS_DIR="$SCRIPT_DIR/research_results"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check requirements
check_requirements() {
    log "Checking requirements..."
    
    if [[ $EUID -ne 0 ]]; then
        echo "❌ This script must be run as root for eBPF tracing"
        echo "Usage: sudo $0 [workload_type]"
        exit 1
    fi
    
    if [[ ! -f "$TRACER" ]]; then
        echo "❌ eBPF tracer not found: $TRACER"
        echo "Run: make clean-categorizer"
        exit 1
    fi
    
    if [[ ! -f "/tmp/minio_dd" ]]; then
        warn "Test binary /tmp/minio_dd not found, creating it..."
        cp /bin/dd /tmp/minio_dd
    fi
    
    log "Requirements check passed ✅"
}

# Test different workload patterns
test_workload() {
    local workload_name="$1"
    local duration="$2"
    local description="$3"
    
    log "Testing workload: $workload_name ($description)"
    
    local output_file="$RESULTS_DIR/${workload_name}_analysis.json"
    local trace_file="$RESULTS_DIR/${workload_name}_trace.log"
    
    info "Starting eBPF tracer for $duration seconds..."
    
    # Start tracer in background
    "$TRACER" -v -i -d "$duration" -o "$trace_file" > "$output_file" 2>&1 &
    local tracer_pid=$!
    
    # Give tracer time to start
    sleep 2
    
    info "Running $workload_name workload..."
    
    # Run the workload
    bash "$WORKLOAD_GENERATOR" "$workload_name"
    
    # Wait for tracer to complete
    wait $tracer_pid 2>/dev/null || true
    
    # Check results
    if [[ -f "$output_file" && -s "$output_file" ]]; then
        log "$workload_name workload completed ✅"
        
        # Show quick summary
        if grep -q "AMPLIFICATION ANALYSIS" "$output_file"; then
            echo ""
            info "Quick results for $workload_name:"
            grep -A 3 "AMPLIFICATION ANALYSIS" "$output_file" || true
            echo ""
        fi
    else
        warn "$workload_name workload produced no output"
    fi
}

# Generate comprehensive research data
generate_research_data() {
    log "Generating comprehensive research data for FAST 2026..."
    
    mkdir -p "$RESULTS_DIR"
    
    # Test each workload type individually
    test_workload "basic" 20 "Basic object operations"
    test_workload "metadata" 15 "Metadata operations"
    test_workload "multipart" 25 "Multipart upload patterns"
    test_workload "erasure" 30 "Erasure coding operations"
    test_workload "admin" 10 "Administrative operations"
    test_workload "mixed" 35 "Mixed realistic workload"
    
    log "Research data generation complete!"
    
    # Generate summary report
    create_summary_report
}

# Create summary report
create_summary_report() {
    local summary_file="$RESULTS_DIR/research_summary.md"
    
    log "Creating research summary report..."
    
    cat > "$summary_file" << EOF
# MinIO I/O Amplification Analysis Results

**Generated:** $(date)
**Framework:** eBPF-based I/O categorization tracer
**Purpose:** FAST 2026 research submission

## Test Results Summary

EOF
    
    for workload in basic metadata multipart erasure admin mixed; do
        local result_file="$RESULTS_DIR/${workload}_analysis.json"
        if [[ -f "$result_file" ]]; then
            echo "### $workload Workload" >> "$summary_file"
            echo "" >> "$summary_file"
            echo "\`\`\`" >> "$summary_file"
            
            # Extract key metrics
            if grep -q "AMPLIFICATION ANALYSIS" "$result_file"; then
                grep -A 10 "AMPLIFICATION ANALYSIS" "$result_file" >> "$summary_file" || true
            fi
            
            echo "\`\`\`" >> "$summary_file"
            echo "" >> "$summary_file"
        fi
    done
    
    cat >> "$summary_file" << EOF

## Research Insights

1. **Data Operations**: Core storage workload efficiency
2. **Metadata Overhead**: System metadata amplification impact  
3. **Amplification Layers**: VFS and block layer contributions
4. **Categorization Success**: Percentage of operations classified

## Next Steps for FAST 2026

1. Compare results across different storage systems
2. Analyze amplification patterns by object size
3. Identify optimization opportunities
4. Generate publication-quality figures

EOF
    
    log "Summary report created: $summary_file"
}

# Quick test function
quick_test() {
    log "Running quick MinIO I/O analysis test..."
    
    info "Starting eBPF tracer for 15 seconds..."
    "$TRACER" -v -i -d 15 &
    local tracer_pid=$!
    
    sleep 2
    
    info "Running mixed workload..."
    bash "$WORKLOAD_GENERATOR" mixed
    
    wait $tracer_pid 2>/dev/null || true
    
    log "Quick test completed ✅"
}

# Main execution
main() {
    log "🔬 MinIO I/O Amplification Analysis Framework"
    log "=============================================="
    
    check_requirements
    
    local command="${1:-quick}"
    
    case "$command" in
        "quick")
            quick_test
            ;;
        "research")
            generate_research_data
            ;;
        "basic"|"metadata"|"multipart"|"erasure"|"admin"|"mixed")
            test_workload "$command" 20 "Individual $command workload test"
            ;;
        "--help"|"-h")
            echo "Usage: sudo $0 [quick|research|basic|metadata|multipart|erasure|admin|mixed]"
            echo ""
            echo "Commands:"
            echo "  quick      - Quick test with mixed workload (default)"
            echo "  research   - Generate comprehensive research data"
            echo "  basic      - Test basic object operations"
            echo "  metadata   - Test metadata operations"
            echo "  multipart  - Test multipart upload patterns"
            echo "  erasure    - Test erasure coding operations"
            echo "  admin      - Test administrative operations"
            echo "  mixed      - Test mixed realistic workload"
            echo ""
            echo "Examples:"
            echo "  sudo $0 quick"
            echo "  sudo $0 research"
            echo "  sudo $0 metadata"
            exit 0
            ;;
        *)
            echo "❌ Unknown command: $command"
            echo "Use: $0 --help for usage information"
            exit 1
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
