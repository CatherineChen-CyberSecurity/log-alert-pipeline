curl -k -u admin:SecretPassword -X GET "https://localhost:9200/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "timestamp": {
        "gte": "2025-06-13T15:00:00.000Z",
        "lt": "2025-06-14T18:00:00.000Z"
      }
    }
  },
  "sort": [
    { "timestamp": "asc" }
  ]
}'