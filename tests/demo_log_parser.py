#!/usr/bin/env python3
"""
Example usage of LogParser class for processing Elasticsearch Wazuh alert data.
"""

import json
from src.log_parser import LogParser

# Sample Elasticsearch response data (based on your provided data)
sample_es_response = {
    "took": 17,
    "timed_out": False,
    "_shards": {
        "total": 3,
        "successful": 3,
        "skipped": 0,
        "failed": 0
    },
    "hits": {
        "total": {
            "value": 2314,
            "relation": "eq"
        },
        "max_score": None,
        "hits": [
            {
                "_index": "wazuh-alerts-4.x-2025.06.14",
                "_id": "neXQbJcBEYs-ge2eTKrR",
                "_score": None,
                "_source": {
                    "agent": {
                        "name": "wazuh.manager",
                        "id": "000"
                    },
                    "manager": {
                        "name": "wazuh.manager"
                    },
                    "data": {
                        "in_iface": "br-a99434df2331,enp0s3",
                        "event_type": "alert",
                        "alert": {
                            "severity": "3",
                            "signature_id": "2200122",
                            "rev": "1",
                            "gid": "1",
                            "signature": "SURICATA AF-PACKET truncated packet",
                            "action": "allowed",
                            "category": "Generic Protocol Command Decode"
                        },
                        "pkt_src": "wire/pcap",
                        "timestamp": "2025-06-14T05:01:11.551182+0000"
                    },
                    "rule": {
                        "firedtimes": 11,
                        "mail": False,
                        "level": 3,
                        "description": "Suricata: Alert - SURICATA AF-PACKET truncated packet",
                        "groups": ["ids", "suricata"],
                        "id": "86601"
                    },
                    "decoder": {
                        "name": "json"
                    },
                    "input": {
                        "type": "log"
                    },
                    "@timestamp": "2025-06-14T05:01:12.871Z",
                    "location": "/var/log/suricata/eve.json",
                    "id": "1749877272.2919366",
                    "timestamp": "2025-06-14T05:01:12.871+0000"
                },
                "sort": [1749877272871]
            }
        ]
    }
}


def main():
    """Demonstrate LogParser usage."""
    # Create LogParser instance
    parser = LogParser()
    
    print("=== LogParser Usage Examples ===\n")
    
    # 1. Extract hit records
    print("1. Extracting hit records:")
    hit_records = parser.extract_hit_records(sample_es_response)
    print(f"   Found {len(hit_records)} hit records")
    print(f"   First record ID: {hit_records[0]['_id']}")
    print()
    
    # 2. Extract source data only
    print("2. Extracting source data:")
    source_data = parser.extract_source_data(sample_es_response)
    print(f"   Found {len(source_data)} source records")
    print(f"   First record agent: {source_data[0]['agent']['name']}")
    print()
    
    # 3. Get search metadata
    print("3. Search metadata:")
    metadata = parser.get_search_metadata(sample_es_response)
    print(f"   Query took: {metadata['took']}ms")
    print(f"   Total hits: {metadata['total_hits']['value']}")
    print(f"   Timed out: {metadata['timed_out']}")
    print()
    
    # 4. Filter by severity
    print("4. Filtering by severity (>= 3):")
    filtered_records = parser.filter_by_severity(sample_es_response, min_severity=3)
    print(f"   Found {len(filtered_records)} records with severity >= 3")
    print()
    
    # 5. Get alert signatures
    print("5. Unique alert signatures:")
    signatures = parser.get_alert_signatures(sample_es_response)
    for sig in signatures:
        print(f"   - {sig}")


if __name__ == "__main__":
    main() 