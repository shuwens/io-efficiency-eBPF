#!/bin/bash

# MinIO Workload Generator for I/O Amplification Analysis
# Generates realistic MinIO workloads to test eBPF categorization framework

set -e

WORKLOAD_DIR="/tmp/minio_workload"
MINIO_BINARY="${1:-/tmp/minio_dd}"  # Use our test binary or real MinIO

echo "🚀 MinIO Workload Generator for I/O Analysis"
echo "=============================================="

# Cleanup and setup
cleanup() {
    echo "🧹 Cleaning up workload directory..."
    rm -rf "$WORKLOAD_DIR"
}

trap cleanup EXIT

setup_minio_structure() {
    echo "📁 Setting up MinIO-like directory structure..."
    
    # Create MinIO data directory structure
    mkdir -p "$WORKLOAD_DIR"/{data1,data2,data3,data4}/.minio.sys/{buckets,config,multipart,tmp,pool}
    mkdir -p "$WORKLOAD_DIR"/logs
    mkdir -p "$WORKLOAD_DIR"/certs
    
    # MinIO bucket metadata
    cat > "$WORKLOAD_DIR/data1/.minio.sys/buckets/research-bucket.json" << 'EOF'
{
  "Name": "research-bucket",
  "Created": "2025-08-22T10:00:00Z",
  "LockEnabled": false,
  "PolicyConfigUpdatedAt": "2025-08-22T10:00:00Z",
  "ObjectLockConfigUpdatedAt": "0001-01-01T00:00:00Z",
  "VersioningConfigUpdatedAt": "2025-08-22T10:00:00Z",
  "LifecycleConfigUpdatedAt": "0001-01-01T00:00:00Z"
}
EOF

    # MinIO configuration
    cat > "$WORKLOAD_DIR/data1/.minio.sys/config/config.json" << 'EOF'
{
  "version": "33",
  "credential": {
    "accessKey": "minioadmin",
    "secretKey": "minioadmin",
    "status": "enabled"
  },
  "region": "us-east-1",
  "browser": "on"
}
EOF

    # Object metadata (xl.meta example)
    cat > "$WORKLOAD_DIR/data1/xl.meta" << 'EOF'
{
  "Version": 1,
  "Format": "xl",
  "Stat": {
    "Size": 1048576,
    "ModTime": "2025-08-22T10:00:00Z"
  },
  "Erasure": {
    "Algorithm": "reedsolomon",
    "DataBlocks": 4,
    "ParityBlocks": 2,
    "BlockSize": 262144,
    "Index": 1,
    "Distribution": [1, 2, 3, 4, 5, 6]
  }
}
EOF

    # Multipart upload metadata
    cat > "$WORKLOAD_DIR/data1/.minio.sys/multipart/upload123.json" << 'EOF'
{
  "uploadId": "upload123",
  "bucket": "research-bucket",
  "object": "large-file.bin",
  "initiated": "2025-08-22T10:00:00Z",
  "parts": [
    {"partNumber": 1, "size": 5242880, "etag": "d41d8cd98f00b204e9800998ecf8427e"},
    {"partNumber": 2, "size": 5242880, "etag": "098f6bcd4621d373cade4e832627b4f6"}
  ]
}
EOF

    echo "✅ MinIO structure created with realistic metadata"
}

# Workload 1: Basic Object Operations
workload_basic_objects() {
    echo "📦 Workload 1: Basic Object Operations"
    echo "   - Small, medium, large object operations"
    echo "   - Tests core data I/O patterns"
    
    # Small objects (< 1KB)
    for i in {1..5}; do
        echo "Small object content $i" > "$WORKLOAD_DIR/data1/small_object_$i"
        if [[ -x "$MINIO_BINARY" ]]; then
            "$MINIO_BINARY" if="$WORKLOAD_DIR/data1/small_object_$i" of=/dev/null 2>/dev/null
        fi
    done
    
    # Medium objects (100KB)
    "$MINIO_BINARY" if=/dev/zero of="$WORKLOAD_DIR/data1/medium_object" bs=100K count=1 2>/dev/null
    "$MINIO_BINARY" if="$WORKLOAD_DIR/data1/medium_object" of=/dev/null 2>/dev/null
    
    # Large objects (10MB) 
    "$MINIO_BINARY" if=/dev/zero of="$WORKLOAD_DIR/data1/large_object" bs=1M count=10 2>/dev/null
    "$MINIO_BINARY" if="$WORKLOAD_DIR/data1/large_object" of=/dev/null bs=1M 2>/dev/null
    
    echo "   ✅ Basic object operations complete"
}

# Workload 2: Metadata Operations
workload_metadata_operations() {
    echo "🗂️  Workload 2: Metadata Operations"
    echo "   - MinIO system metadata access"
    echo "   - Object metadata operations"
    
    # Read bucket metadata
    cat "$WORKLOAD_DIR/data1/.minio.sys/buckets/research-bucket.json" > /dev/null
    
    # Read configuration
    cat "$WORKLOAD_DIR/data1/.minio.sys/config/config.json" > /dev/null
    
    # Read object metadata (xl.meta)
    cat "$WORKLOAD_DIR/data1/xl.meta" > /dev/null
    
    # Update object metadata (simulate metadata update)
    echo '{"Version":1,"Format":"xl","Stat":{"Size":2097152}}' > "$WORKLOAD_DIR/data2/xl.meta"
    cat "$WORKLOAD_DIR/data2/xl.meta" > /dev/null
    
    echo "   ✅ Metadata operations complete"
}

# Workload 3: Multipart Upload Simulation
workload_multipart_upload() {
    echo "📤 Workload 3: Multipart Upload Simulation"
    echo "   - Simulates large file upload with parts"
    echo "   - Tests temporary file operations"
    
    # Create multipart staging area
    mkdir -p "$WORKLOAD_DIR/data1/.minio.sys/tmp/multipart/upload123"
    
    # Simulate multipart parts
    for part in {1..3}; do
        "$MINIO_BINARY" if=/dev/zero of="$WORKLOAD_DIR/data1/.minio.sys/tmp/multipart/upload123/part.$part" bs=5M count=1 2>/dev/null
    done
    
    # Read multipart metadata
    cat "$WORKLOAD_DIR/data1/.minio.sys/multipart/upload123.json" > /dev/null
    
    # Simulate final assembly (copy parts to final object)
    cat "$WORKLOAD_DIR/data1/.minio.sys/tmp/multipart/upload123/part."* > "$WORKLOAD_DIR/data1/assembled_large_file" 2>/dev/null
    
    # Cleanup multipart files (simulate completion)
    rm -f "$WORKLOAD_DIR/data1/.minio.sys/tmp/multipart/upload123/part."*
    
    echo "   ✅ Multipart upload simulation complete"
}

# Workload 4: Erasure Coding Simulation
workload_erasure_coding() {
    echo "🔧 Workload 4: Erasure Coding Simulation"
    echo "   - Simulates MinIO erasure coding operations"
    echo "   - Tests reliability I/O patterns"
    
    # Create erasure coded shards (4+2 configuration)
    for shard in {1..6}; do
        "$MINIO_BINARY" if=/dev/zero of="$WORKLOAD_DIR/data$shard/object.shard$shard" bs=2M count=1 2>/dev/null
        
        # Create corresponding xl.meta for each shard
        echo "{\"Version\":1,\"Format\":\"xl\",\"Erasure\":{\"Index\":$shard}}" > "$WORKLOAD_DIR/data$shard/object.shard$shard.xl.meta"
    done
    
    # Simulate reading shards for reconstruction
    for shard in {1..4}; do  # Only need 4 out of 6 shards
        "$MINIO_BINARY" if="$WORKLOAD_DIR/data$shard/object.shard$shard" of=/dev/null 2>/dev/null
        cat "$WORKLOAD_DIR/data$shard/object.shard$shard.xl.meta" > /dev/null
    done
    
    echo "   ✅ Erasure coding simulation complete"
}

# Workload 5: Administrative Operations
workload_administrative() {
    echo "⚙️  Workload 5: Administrative Operations"
    echo "   - Configuration and logging operations"
    echo "   - Tests administrative overhead"
    
    # Access logs
    echo "$(date -Iseconds) GET /research-bucket/test-object 200 1048576" >> "$WORKLOAD_DIR/logs/access.log"
    cat "$WORKLOAD_DIR/logs/access.log" > /dev/null
    
    # Error logs
    echo "$(date -Iseconds) ERROR Failed to read object: timeout" >> "$WORKLOAD_DIR/logs/error.log"
    cat "$WORKLOAD_DIR/logs/error.log" > /dev/null
    
    # Configuration read
    cat "$WORKLOAD_DIR/data1/.minio.sys/config/config.json" > /dev/null
    
    # SSL certificate simulation
    echo "-----BEGIN CERTIFICATE-----" > "$WORKLOAD_DIR/certs/server.crt"
    echo "MIIBkTCB+wIJAK..." >> "$WORKLOAD_DIR/certs/server.crt"
    cat "$WORKLOAD_DIR/certs/server.crt" > /dev/null
    
    echo "   ✅ Administrative operations complete"
}

# Workload 6: High-Frequency Operations
workload_high_frequency() {
    echo "⚡ Workload 6: High-Frequency Operations"
    echo "   - Small frequent operations"
    echo "   - Tests amplification under load"
    
    # Rapid small writes (simulate key-value workload)
    for i in {1..20}; do
        echo "key$i=value$i" > "$WORKLOAD_DIR/data1/kv_$i"
        cat "$WORKLOAD_DIR/data1/kv_$i" > /dev/null
        # Small delay to see individual operations
        sleep 0.1
    done
    
    echo "   ✅ High-frequency operations complete"
}

# Workload 7: Mixed Workload (Realistic)
workload_mixed_realistic() {
    echo "🔄 Workload 7: Mixed Realistic Workload"
    echo "   - Combination of all operation types"
    echo "   - Most realistic test scenario"
    
    # Concurrent operations
    (
        # Data operations in background
        "$MINIO_BINARY" if=/dev/zero of="$WORKLOAD_DIR/data1/concurrent_large" bs=1M count=8 2>/dev/null
    ) &
    
    (
        # Metadata operations
        for i in {1..3}; do
            cat "$WORKLOAD_DIR/data1/xl.meta" > /dev/null
            sleep 0.5
        done
    ) &
    
    (
        # Administrative operations
        echo "$(date) Mixed workload access" >> "$WORKLOAD_DIR/logs/access.log"
        cat "$WORKLOAD_DIR/logs/access.log" > /dev/null
    ) &
    
    # Wait for concurrent operations
    wait
    
    echo "   ✅ Mixed realistic workload complete"
}

# Main execution
main() {
    echo "📋 Available MinIO Workloads:"
    echo "   1. basic     - Basic object operations (small, medium, large)"
    echo "   2. metadata  - Metadata operations (.minio.sys, xl.meta)"  
    echo "   3. multipart - Multipart upload simulation"
    echo "   4. erasure   - Erasure coding operations"
    echo "   5. admin     - Administrative operations (logs, config)"
    echo "   6. frequency - High-frequency small operations"
    echo "   7. mixed     - Mixed realistic workload"
    echo "   8. all       - Run all workloads sequentially"
    echo ""
    
    WORKLOAD="${1:-all}"
    
    setup_minio_structure
    
    case "$WORKLOAD" in
        "basic"|"1")
            workload_basic_objects
            ;;
        "metadata"|"2")
            workload_metadata_operations
            ;;
        "multipart"|"3")
            workload_multipart_upload
            ;;
        "erasure"|"4")
            workload_erasure_coding
            ;;
        "admin"|"5")
            workload_administrative
            ;;
        "frequency"|"6")
            workload_high_frequency
            ;;
        "mixed"|"7")
            workload_mixed_realistic
            ;;
        "all"|"8"|"")
            echo "🎯 Running ALL workloads for comprehensive analysis..."
            workload_basic_objects
            sleep 1
            workload_metadata_operations
            sleep 1
            workload_multipart_upload
            sleep 1
            workload_erasure_coding
            sleep 1
            workload_administrative
            sleep 1
            workload_high_frequency
            sleep 1
            workload_mixed_realistic
            ;;
        *)
            echo "❌ Unknown workload: $WORKLOAD"
            echo "Use: $0 [basic|metadata|multipart|erasure|admin|frequency|mixed|all]"
            exit 1
            ;;
    esac
    
    echo ""
    echo "🎉 MinIO workload '$WORKLOAD' completed!"
    echo "📊 Check your eBPF tracer output for I/O categorization results"
}

# Usage examples
print_usage_examples() {
    echo ""
    echo "📖 USAGE EXAMPLES:"
    echo ""
    echo "1. Basic object operations:"
    echo "   sudo ./build/clean_working_categorizer -v -i -d 30 &"
    echo "   bash minio_workload_generator.sh basic"
    echo ""
    echo "2. Metadata-focused analysis:"  
    echo "   sudo ./build/clean_working_categorizer -v -d 20 &"
    echo "   bash minio_workload_generator.sh metadata"
    echo ""
    echo "3. Comprehensive analysis:"
    echo "   sudo ./build/clean_working_categorizer -j -d 60 -o full_analysis.json &"
    echo "   bash minio_workload_generator.sh all"
    echo "   python3 analyze_io.py full_analysis.json -v"
    echo ""
    echo "4. Focus on specific I/O sizes:"
    echo "   sudo ./build/clean_working_categorizer -v -m 1024 -d 15 &"
    echo "   bash minio_workload_generator.sh basic"
    echo ""
    echo "💡 TIP: Start your eBPF tracer BEFORE running the workload!"
}

# If run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        print_usage_examples
        exit 0
    fi
    
    main "$@"
    print_usage_examples
fi

