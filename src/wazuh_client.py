import requests
import json
from typing import Optional, Dict, Any, List
import urllib3
import logging

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhClient:
    """Wazuh client class for interacting with Wazuh Indexer"""
    
    def __init__(self, host: str, port: int = 9200, username: str = None, password: str = None):
        """
        Initialize Wazuh client
        
        Args:
            host: Wazuh Indexer IP address or hostname
            port: Port number, default 9200
            username: Username
            password: Password
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"https://{host}:{port}"
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def get_alerts(self, query: Optional[Dict[str, Any]] = None, 
                   index_pattern: str = "wazuh-alerts-*") -> Dict[str, Any]:
        """
        Get Wazuh alerts events
        
        Args:
            query: Elasticsearch query DSL, if None will get all alerts
            index_pattern: Index pattern, default "wazuh-alerts-*"
            
        Returns:
            Dict: Dictionary containing query results
            
        Raises:
            requests.exceptions.RequestException: Raised when request fails
        """
        url = f"{self.base_url}/{index_pattern}/_search"
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        # Set authentication
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        
        # Default query all documents
        if query is None:
            query = {
                "query": {
                    "match_all": {}
                },
                "size": 10
            }
        
        try:
            response = requests.get(
                url=url,
                headers=headers,
                auth=auth,
                json=query,
                verify=False,  # Ignore SSL certificate verification
                timeout=30
            )
            
            # Check response status
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error occurred when getting alerts: {e}")
            raise

    def get_recent_alerts(self, size: int = 100, sort_field: str = "@timestamp") -> Dict[str, Any]:
        """
        Get recent alerts events
        
        Args:
            size: Number of documents to return, default 100
            sort_field: Sort field, default sort by timestamp
            
        Returns:
            Dict: Dictionary containing query results
        """
        query = {
            "query": {
                "match_all": {}
            },
            "sort": [
                {sort_field: {"order": "desc"}}
            ],
            "size": size
        }
        self.logger.info(f"Getting recent alerts with query: {query}")
        return self.get_alerts(query)
    
    def get_alerts_by_time_range(self, start_time: str, end_time: str, size: int = 100) -> Dict[str, Any]:
        """
        Get alerts by time range
        """
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start_time,  
                        "lt": end_time
                    }
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": size
        }
        self.logger.info(f"Getting alerts by time range ({start_time} - {end_time}) with query: {query}")
        return self.get_alerts(query)