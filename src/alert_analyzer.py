from typing import Dict, Any, List, Tuple
import logging
import yaml
import os
from pathlib import Path

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
        
        actual_value = self._get_nested_value(hit, field)
        
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
        
        for hit in hits:
            for rule in self.rules:
                if self._match_rule(hit, rule):
                    matched_alerts.append((hit, rule))
                    self.logger.debug(f"Hit matched rule {rule.get('rule_id', 'unknown')}: {rule.get('rule_name', 'unnamed')}")
                    break  # Stop at first matching rule
        
        self.logger.info(f"Found {len(matched_alerts)} matching alerts")
        return matched_alerts

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
        