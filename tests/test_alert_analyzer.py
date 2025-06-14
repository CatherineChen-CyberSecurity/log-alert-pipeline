import unittest
import os
import tempfile
import yaml
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from alert_analyzer import AlertAnalyzer
from test_alert_analyzer_cases import test_case_success, test_case_level_fail, test_case_src_ip_fail


class TestAlertAnalyzer(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures before each test method."""
        # Create a temporary configuration file
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        self.test_rules = {
            'rules': [
                {
                    'rule_id': 1,
                    'rule_name': 'Alert 1',
                    'rule_description': 'Alert 1 description',
                    'rule_actions': [
                        {
                            'action': 'email',
                            'email': 'admin@example.com'
                        }
                    ],
                    'filter': [
                        {
                            'field': 'data.src_ip',
                            'operator': 'eq',
                            'value': '172.21.0.11'
                        },
                        {
                            'field': 'data.dest_ip',
                            'operator': 'eq',
                            'value': '172.21.0.10'
                        },
                        {
                            'field': 'rule.level',
                            'operator': 'gt',
                            'value': 3
                        }
                    ]
                }
            ]
        }
        
        yaml.dump(self.test_rules, self.temp_config)
        self.temp_config.close()
        
        # Initialize analyzer with test config
        self.analyzer = AlertAnalyzer(config_path=self.temp_config.name)
    
    def tearDown(self):
        """Clean up after each test method."""
        # Remove temporary config file
        os.unlink(self.temp_config.name)
    
    def test_load_rules_success(self):
        """Test successful loading of rules from configuration file."""
        rules = self.analyzer.rules
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['rule_id'], 1)
        self.assertEqual(rules[0]['rule_name'], 'Alert 1')
        self.assertEqual(len(rules[0]['filter']), 3)
    
    def test_load_rules_file_not_found(self):
        """Test handling of missing configuration file."""
        analyzer = AlertAnalyzer(config_path="nonexistent.yaml")
        self.assertEqual(len(analyzer.rules), 0)
    
    def test_get_nested_value_simple(self):
        """Test getting nested values from dictionary."""
        data = {'rule': {'level': 4}}
        value = self.analyzer._get_nested_value(data, 'rule.level')
        self.assertEqual(value, 4)
    
    def test_get_nested_value_deep(self):
        """Test getting deeply nested values."""
        data = {'data': {'src_ip': '172.21.0.11'}}
        value = self.analyzer._get_nested_value(data, 'data.src_ip')
        self.assertEqual(value, '172.21.0.11')
    
    def test_get_nested_value_not_found(self):
        """Test handling of non-existent nested keys."""
        data = {'rule': {'level': 4}}
        value = self.analyzer._get_nested_value(data, 'rule.nonexistent')
        self.assertIsNone(value)
    
    def test_evaluate_condition_eq_true(self):
        """Test equality condition evaluation - true case."""
        hit = {'data': {'src_ip': '172.21.0.11'}}
        condition = {'field': 'data.src_ip', 'operator': 'eq', 'value': '172.21.0.11'}
        result = self.analyzer._evaluate_condition(hit, condition)
        self.assertTrue(result)
    
    def test_evaluate_condition_eq_false(self):
        """Test equality condition evaluation - false case."""
        hit = {'data': {'src_ip': '1.1.1.1'}}
        condition = {'field': 'data.src_ip', 'operator': 'eq', 'value': '172.21.0.11'}
        result = self.analyzer._evaluate_condition(hit, condition)
        self.assertFalse(result)
    
    def test_evaluate_condition_gt_true(self):
        """Test greater than condition evaluation - true case."""
        hit = {'rule': {'level': 5}}
        condition = {'field': 'rule.level', 'operator': 'gt', 'value': 3}
        result = self.analyzer._evaluate_condition(hit, condition)
        self.assertTrue(result)
    
    def test_evaluate_condition_gt_false(self):
        """Test greater than condition evaluation - false case."""
        hit = {'rule': {'level': 2}}
        condition = {'field': 'rule.level', 'operator': 'gt', 'value': 3}
        result = self.analyzer._evaluate_condition(hit, condition)
        self.assertFalse(result)
    
    def test_evaluate_condition_operators(self):
        """Test various operators."""
        hit = {'value': 10}
        
        # Test ne (not equal)
        condition = {'field': 'value', 'operator': 'ne', 'value': 5}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
        
        # Test lt (less than)
        condition = {'field': 'value', 'operator': 'lt', 'value': 15}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
        
        # Test gte (greater than or equal)
        condition = {'field': 'value', 'operator': 'gte', 'value': 10}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
        
        # Test lte (less than or equal)
        condition = {'field': 'value', 'operator': 'lte', 'value': 10}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
    
    def test_evaluate_condition_string_operators(self):
        """Test string-specific operators."""
        hit = {'message': 'Hello World'}
        
        # Test contains
        condition = {'field': 'message', 'operator': 'contains', 'value': 'World'}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
        
        # Test startswith
        condition = {'field': 'message', 'operator': 'startswith', 'value': 'Hello'}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
        
        # Test endswith
        condition = {'field': 'message', 'operator': 'endswith', 'value': 'World'}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
    
    def test_evaluate_condition_in_operator(self):
        """Test 'in' operator."""
        hit = {'category': 'error'}
        condition = {'field': 'category', 'operator': 'in', 'value': ['error', 'warning']}
        self.assertTrue(self.analyzer._evaluate_condition(hit, condition))
        
        condition = {'field': 'category', 'operator': 'in', 'value': ['info', 'debug']}
        self.assertFalse(self.analyzer._evaluate_condition(hit, condition))
    
    def test_evaluate_condition_invalid_operator(self):
        """Test handling of invalid operators."""
        hit = {'value': 10}
        condition = {'field': 'value', 'operator': 'invalid', 'value': 5}
        result = self.analyzer._evaluate_condition(hit, condition)
        self.assertFalse(result)
    
    def test_match_rule_success(self):
        """Test successful rule matching."""
        hit = test_case_success['_source']
        rule = self.test_rules['rules'][0]
        result = self.analyzer._match_rule(hit, rule)
        self.assertTrue(result)
    
    def test_match_rule_no_filters(self):
        """Test rule matching with no filters (should match all)."""
        hit = {'any': 'data'}
        rule = {'rule_id': 1, 'filter': []}
        result = self.analyzer._match_rule(hit, rule)
        self.assertTrue(result)
    
    # MANDATORY TEST CASE 1: Success case - all conditions match
    def test_analyze_alert_success_case(self):
        """Test alert analysis with successful matching case."""
        hits = [test_case_success['_source']]
        results = self.analyzer.analyze_alert(hits)
        
        self.assertEqual(len(results), 1)
        matched_hit, matched_rule = results[0]
        self.assertEqual(matched_hit, test_case_success['_source'])
        self.assertEqual(matched_rule['rule_id'], 1)
    
    # MANDATORY TEST CASE 2: Fail case - level condition not met
    def test_analyze_alert_level_fail_case(self):
        """Test alert analysis with level condition failure."""
        hits = [test_case_level_fail['_source']]
        results = self.analyzer.analyze_alert(hits)
        
        # Should not match because level=2 does not satisfy > 3
        self.assertEqual(len(results), 0)
    
    # MANDATORY TEST CASE 3: Fail case - src_ip condition not met
    def test_analyze_alert_src_ip_fail_case(self):
        """Test alert analysis with src_ip condition failure."""
        hits = [test_case_src_ip_fail['_source']]
        results = self.analyzer.analyze_alert(hits)
        
        # Should not match because src_ip='1.1.1.1' does not equal '172.21.0.11'
        self.assertEqual(len(results), 0)
    
    def test_analyze_alert_multiple_hits(self):
        """Test alert analysis with multiple hits."""
        hits = [
            test_case_success['_source'],
            test_case_level_fail['_source'],
            test_case_src_ip_fail['_source']
        ]
        results = self.analyzer.analyze_alert(hits)
        
        # Only the success case should match
        self.assertEqual(len(results), 1)
        matched_hit, matched_rule = results[0]
        self.assertEqual(matched_hit, test_case_success['_source'])
    
    def test_get_matched_alerts_by_rule(self):
        """Test grouping of matched alerts by rule."""
        hits = [test_case_success['_source']]
        grouped_results = self.analyzer.get_matched_alerts_by_rule(hits)
        
        self.assertIn('1', grouped_results)
        self.assertEqual(len(grouped_results['1']), 1)
        self.assertEqual(grouped_results['1'][0], test_case_success['_source'])
    
    def test_get_matched_alerts_by_rule_multiple_rules(self):
        """Test grouping with multiple rules."""
        # Add another rule to test configuration
        additional_rule = {
            'rule_id': 2,
            'rule_name': 'Alert 2',
            'filter': [
                {'field': 'rule.level', 'operator': 'eq', 'value': 2}
            ]
        }
        self.analyzer.rules.append(additional_rule)
        
        hits = [test_case_success['_source'], test_case_level_fail['_source']]
        grouped_results = self.analyzer.get_matched_alerts_by_rule(hits)
        
        # Success case matches rule 1, level_fail case matches rule 2
        self.assertIn('1', grouped_results)
        self.assertIn('2', grouped_results)
        self.assertEqual(len(grouped_results['1']), 1)
        self.assertEqual(len(grouped_results['2']), 1)
    
    def test_reload_rules(self):
        """Test reloading rules from configuration file."""
        # Modify the temporary config file
        new_rules = {
            'rules': [
                {
                    'rule_id': 999,
                    'rule_name': 'New Rule',
                    'filter': []
                }
            ]
        }
        
        with open(self.temp_config.name, 'w') as f:
            yaml.dump(new_rules, f)
        
        # Reload rules
        self.analyzer.reload_rules()
        
        # Check that new rules are loaded
        self.assertEqual(len(self.analyzer.rules), 1)
        self.assertEqual(self.analyzer.rules[0]['rule_id'], 999)
        self.assertEqual(self.analyzer.rules[0]['rule_name'], 'New Rule')
    
    def test_analyze_alert_empty_hits(self):
        """Test analysis with empty hits list."""
        results = self.analyzer.analyze_alert([])
        self.assertEqual(len(results), 0)
    
    def test_analyze_alert_malformed_hit(self):
        """Test analysis with malformed hit data."""
        malformed_hit = {'incomplete': 'data'}
        results = self.analyzer.analyze_alert([malformed_hit])
        self.assertEqual(len(results), 0)
    
    @patch('alert_analyzer.logging.getLogger')
    def test_logging_calls(self, mock_logger):
        """Test that logging is called appropriately."""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance
        
        analyzer = AlertAnalyzer(config_path=self.temp_config.name)
        hits = [test_case_success['_source']]
        analyzer.analyze_alert(hits)
        
        # Check that info logging was called
        mock_logger_instance.info.assert_called()


if __name__ == '__main__':
    unittest.main()
