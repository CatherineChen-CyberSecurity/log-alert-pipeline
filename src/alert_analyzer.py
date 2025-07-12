from typing import Dict, Any, List, Tuple
import logging
import yaml
import os
from pathlib import Path
import pandas as pd

class AlertAnalyzer:
    def __init__(self, config_path: str = "config/alert_rule.yaml"):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load alert rules from YAML configuration file"""
        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                self.logger.error(f"Configuration file not found: {self.config_path}")
                return []
            
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                rules = config.get('rules', [])
                self.logger.info(f"Loaded {len(rules)} alert rules from {self.config_path}")
                return rules
        except Exception as e:
            self.logger.error(f"Error loading rules from {self.config_path}: {e}")
            return []

    def _get_nested_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """Get nested value from dictionary using dot notation (e.g., 'data.src_ip')"""
        try:
            keys = field_path.split('.')
            value = data
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
            return value
        except Exception:
            return None

    def _evaluate_condition(self, hit: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Evaluate a single filter condition against a hit"""
        field = condition.get('field')
        operator = condition.get('operator')
        expected_value = condition.get('value')
        
        if not all([field, operator]):
            return False
        
        value = hit.get('_source', hit)
        actual_value = self._get_nested_value(value, field)
        
        # Handle different operators
        try:
            if operator == 'eq':
                return actual_value == expected_value
            elif operator == 'ne':
                return actual_value != expected_value
            elif operator == 'gt':
                return actual_value > expected_value
            elif operator == 'lt':
                return actual_value < expected_value
            elif operator == 'gte':
                return actual_value >= expected_value
            elif operator == 'lte':
                return actual_value <= expected_value
            elif operator == 'in':
                return actual_value in expected_value if isinstance(expected_value, list) else False
            elif operator == 'contains':
                return expected_value in str(actual_value) if actual_value is not None else False
            elif operator == 'startswith':
                return str(actual_value).startswith(str(expected_value)) if actual_value is not None else False
            elif operator == 'endswith':
                return str(actual_value).endswith(str(expected_value)) if actual_value is not None else False
            else:
                self.logger.warning(f"Unknown operator: {operator}")
                return False
        except Exception as e:
            self.logger.debug(f"Error evaluating condition {condition}: {e}")
            return False

    def _match_rule(self, hit: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if a hit matches all conditions in a rule"""
        filters = rule.get('filter', [])
        if not filters:
            return True  # No filters means match all
        
        # All conditions must be true (AND logic)
        for condition in filters:
            if not self._evaluate_condition(hit, condition):
                return False
        
        return True

    def analyze_alert(self, hits: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """
        Analyze alerts and filter them based on configured rules
        
        Args:
            hits: List of alert hits to analyze
            
        Returns:
            List of tuples containing (hit, matched_rule)
        """
        self.logger.info(f"Analyzing {len(hits)} alerts against {len(self.rules)} rules")
        
        matched_alerts = []
        
        # Segregate hits by rule type
        for rule in self.rules:
            if 'aggregation' in rule:
                # This is an aggregation rule, process it separately
                aggregation_alerts = self._evaluate_aggregation_rule(hits, rule)
                matched_alerts.extend(aggregation_alerts)
            else:
                # This is a simple rule, process it hit by hit
                for hit in hits:
                    if self._match_rule(hit, rule):
                        matched_alerts.append((hit, rule))
                        self.logger.debug(f"Hit matched rule {rule.get('rule_id', 'unknown')}: {rule.get('rule_name', 'unnamed')}")
        
        self.logger.info(f"Found {len(matched_alerts)} matching alerts")
        return matched_alerts

    def _evaluate_aggregation_rule(self, hits: List[Dict[str, Any]], rule: Dict[str, Any]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Evaluate an aggregation rule against a list of hits."""
        agg_config = rule.get('aggregation', {})
        time_window = agg_config.get('time_window')
        group_by = agg_config.get('group_by')
        unique_count_field = agg_config.get('unique_count_field')
        threshold = agg_config.get('threshold')

        if not all([time_window, group_by, unique_count_field, threshold]):
            self.logger.warning(f"Invalid aggregation configuration in rule {rule.get('rule_id')}")
            return []

        # Filter hits that match the rule's base filter
        filtered_hits = [h for h in hits if self._match_rule(h, rule)]
        if not filtered_hits:
            return []

        # Create a DataFrame for easier analysis
        df = pd.DataFrame([self._flatten_dict(h['_source']) for h in filtered_hits])
        
        # Ensure timestamp column exists and is in the correct format
        if 'timestamp' not in df.columns:
            self.logger.warning("Aggregation rule requires 'timestamp' field in data")
            return []
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Group by the specified field and apply time window logic
        grouped = df.groupby(group_by)
        
        aggregated_alerts = []

        for group_name, group_df in grouped:
            group_df = group_df.sort_values(by='timestamp')
            
            # Use a rolling window to check for the condition
            for i in range(len(group_df)):
                end_time = group_df.iloc[i]['timestamp']
                start_time = end_time - pd.Timedelta(seconds=time_window)
                
                window_df = group_df[(group_df['timestamp'] >= start_time) & (group_df['timestamp'] <= end_time)]
                
                unique_count = window_df[unique_count_field].nunique()
                
                if unique_count >= threshold:
                    # Create a synthetic alert representing the aggregation
                    first_hit_in_window = window_df.iloc[0]
                    last_hit_in_window = window_df.iloc[-1]
                    
                    dest_ips = list(window_df['data.dest_ip'].unique())

                    synthetic_alert = {
                        'aggregation_summary': True,
                        'rule_id': rule.get('rule_id'),
                        'rule_name': rule.get('rule_name'),
                        'start_time': str(start_time),
                        'end_time': str(end_time),
                        'group_key': group_name,
                        'triggering_value': unique_count,
                        'threshold': threshold,
                        'dest_port_count': unique_count,
                        'src_ip': first_hit_in_window.to_dict().get('data.src_ip'),
                        'dest_ip': dest_ips,
                    }
                    aggregated_alerts.append((synthetic_alert, rule))
                    
                    # To avoid creating multiple alerts for the same ongoing scan, 
                    # we could add more complex logic here to "snooze" this group.
                    # For now, we break after the first trigger in this group for simplicity.
                    break
        
        return aggregated_alerts

    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str ='.') -> Dict[str, Any]:
        """Flatten a nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def get_matched_alerts_by_rule(self, hits: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get alerts grouped by matching rule
        
        Args:
            hits: List of alert hits to analyze
            
        Returns:
            Dictionary with rule_id as key and list of matching hits as value
        """
        matched_alerts = self.analyze_alert(hits)
        grouped_alerts = {}
        
        for hit, rule in matched_alerts:
            rule_id = str(rule.get('rule_id', 'unknown'))
            if rule_id not in grouped_alerts:
                grouped_alerts[rule_id] = []
            grouped_alerts[rule_id].append(hit)
        
        return grouped_alerts

    def reload_rules(self):
        """Reload rules from configuration file"""
        self.rules = self._load_rules()
        