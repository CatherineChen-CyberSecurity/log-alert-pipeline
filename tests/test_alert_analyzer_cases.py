# Test cases for AlertAnalyzer

# Test case 1: Success case - all conditions match
test_case_success = {
    "_index": "wazuh-alerts-4.x-2025.06.14",
    "_id": "XnQbbpcBNwZXY7pbJ4n8",
    "_version": 1,
    "_score": None,
    "_source": {
        "input": {
            "type": "log"
        },
        "agent": {
            "name": "wazuh.manager",
            "id": "000"
        },
        "manager": {
            "name": "wazuh.manager"
        },
        "data": {
            "in_iface": "br-a99434df2331",
            "src_ip": "172.21.0.11",  # Match condition
            "src_port": "47313",
            "tcp": {
                "rst": "true",
                "tcp_flags_ts": "02",
                "tcp_flags_tc": "14",
                "tcp_flags": "16",
                "ack": "true",
                "ts_max_regions": "1",
                "syn": "true",
                "state": "closed",
                "tc_max_regions": "1"
            },
            "event_type": "flow",
            "flow_id": "920816500254575.000000",
            "dest_ip": "172.21.0.10",  # Match condition
            "proto": "TCP",
            "dest_port": "1166",
            "flow": {
                "reason": "timeout",
                "pkts_toserver": "1",
                "alerted": "false",
                "start": "2025-06-14T11:01:31.017786+0000",
                "bytes_toclient": "54",
                "end": "2025-06-14T11:01:31.017933+0000",
                "state": "closed",
                "bytes_toserver": "58",
                "pkts_toclient": "1",
                "age": "0"
            },
            "timestamp": "2025-06-14T11:02:41.330644+0000"
        },
        "rule": {
            "firedtimes": 11898,
            "mail": False,
            "level": 4,  # Match condition (> 3)
            "description": "Suricata: Traffic observed from monitored IP 172.21.0.11 to 172.21.0.10.",
            "groups": [
                "local",
                "syslog",
                "sshd",
                "suricata",
                "monitored_ip"
            ],
            "id": "100100"
        },
        "location": "/var/log/suricata/eve.json",
        "decoder": {
            "name": "json"
        },
        "id": "1749898961.23385259",
        "full_log": "{\"timestamp\":\"2025-06-14T11:02:41.330644+0000\",\"flow_id\":920816500254575,\"in_iface\":\"br-a99434df2331\",\"event_type\":\"flow\",\"src_ip\":\"172.21.0.11\",\"src_port\":47313,\"dest_ip\":\"172.21.0.10\",\"dest_port\":1166,\"proto\":\"TCP\",\"flow\":{\"pkts_toserver\":1,\"pkts_toclient\":1,\"bytes_toserver\":58,\"bytes_toclient\":54,\"start\":\"2025-06-14T11:01:31.017786+0000\",\"end\":\"2025-06-14T11:01:31.017933+0000\",\"age\":0,\"state\":\"closed\",\"reason\":\"timeout\",\"alerted\":false},\"tcp\":{\"tcp_flags\":\"16\",\"tcp_flags_ts\":\"02\",\"tcp_flags_tc\":\"14\",\"syn\":true,\"rst\":true,\"ack\":true,\"state\":\"closed\",\"ts_max_regions\":1,\"tc_max_regions\":1}}",
        "timestamp": "2025-06-14T11:02:41.509+0000"
    },
    "fields": {
        "timestamp": [
            "2025-06-14T11:02:41.509Z"
        ],
        "data.timestamp": [
            "2025-06-14T11:02:41.330Z"
        ]
    },
    "highlight": {
        "data.dest_ip": [
            "@opensearch-dashboards-highlighted-field@172.21.0.10@/opensearch-dashboards-highlighted-field@"
        ]
    },
    "sort": [
        1749898961509
    ]
}

# Test case 2: rule.level=2 does not match - level condition not satisfied
test_case_level_fail = {
    "_index": "wazuh-alerts-4.x-2025.06.14",
    "_id": "XnQbbpcBNwZXY7pbJ4n9",
    "_version": 1,
    "_score": None,
    "_source": {
        "input": {
            "type": "log"
        },
        "agent": {
            "name": "wazuh.manager",
            "id": "000"
        },
        "manager": {
            "name": "wazuh.manager"
        },
        "data": {
            "in_iface": "br-a99434df2331",
            "src_ip": "172.21.0.11",  # Match condition
            "src_port": "47313",
            "tcp": {
                "rst": "true",
                "tcp_flags_ts": "02",
                "tcp_flags_tc": "14",
                "tcp_flags": "16",
                "ack": "true",
                "ts_max_regions": "1",
                "syn": "true",
                "state": "closed",
                "tc_max_regions": "1"
            },
            "event_type": "flow",
            "flow_id": "920816500254575.000000",
            "dest_ip": "172.21.0.10",  # Match condition
            "proto": "TCP",
            "dest_port": "1166",
            "flow": {
                "reason": "timeout",
                "pkts_toserver": "1",
                "alerted": "false",
                "start": "2025-06-14T11:01:31.017786+0000",
                "bytes_toclient": "54",
                "end": "2025-06-14T11:01:31.017933+0000",
                "state": "closed",
                "bytes_toserver": "58",
                "pkts_toclient": "1",
                "age": "0"
            },
            "timestamp": "2025-06-14T11:02:41.330644+0000"
        },
        "rule": {
            "firedtimes": 11898,
            "mail": False,
            "level": 2,  # Does not match condition (not > 3)
            "description": "Suricata: Traffic observed from monitored IP 172.21.0.11 to 172.21.0.10.",
            "groups": [
                "local",
                "syslog",
                "sshd",
                "suricata",
                "monitored_ip"
            ],
            "id": "100100"
        },
        "location": "/var/log/suricata/eve.json",
        "decoder": {
            "name": "json"
        },
        "id": "1749898961.23385260",
        "full_log": "{\"timestamp\":\"2025-06-14T11:02:41.330644+0000\",\"flow_id\":920816500254575,\"in_iface\":\"br-a99434df2331\",\"event_type\":\"flow\",\"src_ip\":\"172.21.0.11\",\"src_port\":47313,\"dest_ip\":\"172.21.0.10\",\"dest_port\":1166,\"proto\":\"TCP\",\"flow\":{\"pkts_toserver\":1,\"pkts_toclient\":1,\"bytes_toserver\":58,\"bytes_toclient\":54,\"start\":\"2025-06-14T11:01:31.017786+0000\",\"end\":\"2025-06-14T11:01:31.017933+0000\",\"age\":0,\"state\":\"closed\",\"reason\":\"timeout\",\"alerted\":false},\"tcp\":{\"tcp_flags\":\"16\",\"tcp_flags_ts\":\"02\",\"tcp_flags_tc\":\"14\",\"syn\":true,\"rst\":true,\"ack\":true,\"state\":\"closed\",\"ts_max_regions\":1,\"tc_max_regions\":1}}",
        "timestamp": "2025-06-14T11:02:41.509+0000"
    },
    "fields": {
        "timestamp": [
            "2025-06-14T11:02:41.509Z"
        ],
        "data.timestamp": [
            "2025-06-14T11:02:41.330Z"
        ]
    },
    "highlight": {
        "data.dest_ip": [
            "@opensearch-dashboards-highlighted-field@172.21.0.10@/opensearch-dashboards-highlighted-field@"
        ]
    },
    "sort": [
        1749898961509
    ]
}

# Test case 3: data.src_ip=1.1.1.1 does not match - src_ip condition not satisfied
test_case_src_ip_fail = {
    "_index": "wazuh-alerts-4.x-2025.06.14",
    "_id": "XnQbbpcBNwZXY7pbJ4n0",
    "_version": 1,
    "_score": None,
    "_source": {
        "input": {
            "type": "log"
        },
        "agent": {
            "name": "wazuh.manager",
            "id": "000"
        },
        "manager": {
            "name": "wazuh.manager"
        },
        "data": {
            "in_iface": "br-a99434df2331",
            "src_ip": "1.1.1.1",  # Does not match condition (not equal to 172.21.0.11)
            "src_port": "47313",
            "tcp": {
                "rst": "true",
                "tcp_flags_ts": "02",
                "tcp_flags_tc": "14",
                "tcp_flags": "16",
                "ack": "true",
                "ts_max_regions": "1",
                "syn": "true",
                "state": "closed",
                "tc_max_regions": "1"
            },
            "event_type": "flow",
            "flow_id": "920816500254575.000000",
            "dest_ip": "172.21.0.10",  # Match condition
            "proto": "TCP",
            "dest_port": "1166",
            "flow": {
                "reason": "timeout",
                "pkts_toserver": "1",
                "alerted": "false",
                "start": "2025-06-14T11:01:31.017786+0000",
                "bytes_toclient": "54",
                "end": "2025-06-14T11:01:31.017933+0000",
                "state": "closed",
                "bytes_toserver": "58",
                "pkts_toclient": "1",
                "age": "0"
            },
            "timestamp": "2025-06-14T11:02:41.330644+0000"
        },
        "rule": {
            "firedtimes": 11898,
            "mail": False,
            "level": 4,  # Match condition (> 3)
            "description": "Suricata: Traffic observed from monitored IP 1.1.1.1 to 172.21.0.10.",
            "groups": [
                "local",
                "syslog",
                "sshd",
                "suricata",
                "monitored_ip"
            ],
            "id": "100100"
        },
        "location": "/var/log/suricata/eve.json",
        "decoder": {
            "name": "json"
        },
        "id": "1749898961.23385261",
        "full_log": "{\"timestamp\":\"2025-06-14T11:02:41.330644+0000\",\"flow_id\":920816500254575,\"in_iface\":\"br-a99434df2331\",\"event_type\":\"flow\",\"src_ip\":\"1.1.1.1\",\"src_port\":47313,\"dest_ip\":\"172.21.0.10\",\"dest_port\":1166,\"proto\":\"TCP\",\"flow\":{\"pkts_toserver\":1,\"pkts_toclient\":1,\"bytes_toserver\":58,\"bytes_toclient\":54,\"start\":\"2025-06-14T11:01:31.017786+0000\",\"end\":\"2025-06-14T11:01:31.017933+0000\",\"age\":0,\"state\":\"closed\",\"reason\":\"timeout\",\"alerted\":false},\"tcp\":{\"tcp_flags\":\"16\",\"tcp_flags_ts\":\"02\",\"tcp_flags_tc\":\"14\",\"syn\":true,\"rst\":true,\"ack\":true,\"state\":\"closed\",\"ts_max_regions\":1,\"tc_max_regions\":1}}",
        "timestamp": "2025-06-14T11:02:41.509+0000"
    },
    "fields": {
        "timestamp": [
            "2025-06-14T11:02:41.509Z"
        ],
        "data.timestamp": [
            "2025-06-14T11:02:41.330Z"
        ]
    },
    "highlight": {
        "data.src_ip": [
            "@opensearch-dashboards-highlighted-field@1.1.1.1@/opensearch-dashboards-highlighted-field@"
        ]
    },
    "sort": [
        1749898961509
    ]
} 