import json
from typing import List, Dict, Any, Optional


class LogParser:
    """
    A parser class for extracting hit records from Elasticsearch search results.
    Specifically designed for Wazuh security alert data.
    """
    
    def __init__(self):
        """Initialize the LogParser."""
        pass
    
    def extract_hit_records(self, es_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract hit records from Elasticsearch search response.
        
        Args:
            es_response: The Elasticsearch search response as a dictionary
            
        Returns:
            List of hit records, each containing _index, _id, _score, _source, etc.
            
        Raises:
            ValueError: If the response format is invalid
        """
        try:
            # Check if the response has the expected structure
            if not isinstance(es_response, dict):
                raise ValueError("Response must be a dictionary")
            
            if 'hits' not in es_response:
                raise ValueError("Response must contain 'hits' field")
            
            hits_container = es_response['hits']
            if not isinstance(hits_container, dict) or 'hits' not in hits_container:
                raise ValueError("Invalid hits structure in response")
            
            # Extract the actual hit records
            hit_records = hits_container['hits']
            
            if not isinstance(hit_records, list):
                raise ValueError("Hit records must be a list")
            
            return hit_records
            
        except Exception as e:
            raise ValueError(f"Failed to extract hit records: {str(e)}")
    
    def extract_source_data(self, es_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract only the _source data from hit records.
        
        Args:
            es_response: The Elasticsearch search response as a dictionary
            
        Returns:
            List of _source data dictionaries
        """
        hit_records = self.extract_hit_records(es_response)
        source_data = []
        
        for hit in hit_records:
            if '_source' in hit:
                source_data.append(hit['_source'])
        
        return source_data
    
    def get_search_metadata(self, es_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract search metadata from Elasticsearch response.
        
        Args:
            es_response: The Elasticsearch search response as a dictionary
            
        Returns:
            Dictionary containing search metadata (took, total hits, etc.)
        """
        metadata = {}
        
        # Basic search info
        metadata['took'] = es_response.get('took', 0)
        metadata['timed_out'] = es_response.get('timed_out', False)
        
        # Shard information
        if '_shards' in es_response:
            metadata['shards'] = es_response['_shards']
        
        # Hit count information
        if 'hits' in es_response and 'total' in es_response['hits']:
            metadata['total_hits'] = es_response['hits']['total']
            metadata['max_score'] = es_response['hits'].get('max_score')
        
        return metadata
    
    def filter_by_severity(self, es_response: Dict[str, Any], min_severity: int = 1) -> List[Dict[str, Any]]:
        """
        Filter hit records by alert severity level.
        
        Args:
            es_response: The Elasticsearch search response as a dictionary
            min_severity: Minimum severity level to include (default: 1)
            
        Returns:
            List of hit records with severity >= min_severity
        """
        hit_records = self.extract_hit_records(es_response)
        filtered_records = []
        
        for hit in hit_records:
            source = hit.get('_source', {})
            data = source.get('data', {})
            alert = data.get('alert', {})
            
            severity = alert.get('severity')
            if severity:
                try:
                    severity_int = int(severity)
                    if severity_int >= min_severity:
                        filtered_records.append(hit)
                except ValueError:
                    # Skip records with invalid severity format
                    continue
        
        return filtered_records
    
    def get_alert_signatures(self, es_response: Dict[str, Any]) -> List[str]:
        """
        Extract unique alert signatures from the hit records.
        
        Args:
            es_response: The Elasticsearch search response as a dictionary
            
        Returns:
            List of unique alert signatures
        """
        hit_records = self.extract_hit_records(es_response)
        signatures = set()
        
        for hit in hit_records:
            source = hit.get('_source', {})
            data = source.get('data', {})
            alert = data.get('alert', {})
            
            signature = alert.get('signature')
            if signature:
                signatures.add(signature)
        
        return list(signatures)
