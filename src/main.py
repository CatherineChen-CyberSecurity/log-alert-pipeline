#!/usr/bin/env python3
"""
Wazuh Data Fetcher - Scheduled data retrieval framework
This module provides a framework for fetching Wazuh alert data every 5 minutes
"""

import schedule
import time
import yaml
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add the src directory to the Python path
sys.path.append(str(Path(__file__).parent))

from wazuh_client import WazuhClient
from log_parser import LogParser


class WazuhDataFetcher:
    """
    A scheduled data fetcher for Wazuh alerts
    Fetches data every 5 minutes and prints alert IDs
    """
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        """
        Initialize the data fetcher
        
        Args:
            config_path: Path to the configuration file
        """
        self.config = self._load_config(config_path)
        self._setup_logging()
        self.client = self._initialize_client()
        self.logger = logging.getLogger(__name__)
        self.parser = LogParser()
        self.last_request_time = None
        
    def _load_config(self, config_path: str) -> dict:
        """
        Load configuration from YAML file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            dict: Configuration dictionary
        """
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            print(f"Configuration file not found: {config_path}")
            return self._get_default_config()
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> dict:
        """
        Get default configuration
        
        Returns:
            dict: Default configuration
        """
        return {
            'wazuh': {
                'host': 'localhost',
                'port': 9200,
                'username': 'admin',
                'password': 'admin'
            },
            'scheduler': {
                'interval_minutes': 5,
                'alert_fetch_size': 20
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        level = getattr(logging, log_config.get('level', 'INFO'))
        format_str = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        logging.basicConfig(
            level=level,
            format=format_str,
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('logs/wazuh_fetcher.log', mode='a')
            ]
        )
    
    def _initialize_client(self) -> WazuhClient:
        """
        Initialize Wazuh client
        
        Returns:
            WazuhClient: Initialized client instance
        """
        wazuh_config = self.config.get('wazuh', {})
        return WazuhClient(
            host=wazuh_config.get('host', 'localhost'),
            port=wazuh_config.get('port', 9200),
            username=wazuh_config.get('username'),
            password=wazuh_config.get('password')
        )
    
    def fetch_and_print_ids(self):
        """
        Fetch Wazuh alert data and print IDs
        This method is called every 5 minutes
        """
        try:
            fetch_size = self.config.get('scheduler', {}).get('alert_fetch_size', 20)
            
            self.logger.info(f"Fetching {fetch_size} recent alerts...")
            if self.last_request_time is None:
                self.last_request_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                alerts = self.client.get_recent_alerts(size=fetch_size)
            else:
                self.last_request_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                alerts = self.client.get_alerts_by_time_range(self.last_request_time, datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"), size=fetch_size)
            
            # Parse alerts
            alert_events = self.parser.extract_hit_records(alerts)
            
            # Print alerts
            for alert_event in alert_events:
                # 安全地获取字段，处理可能不存在的字段
                timestamp = alert_event.get('_source', {}).get('timestamp', 'N/A')
                severity = alert_event.get('_source', {}).get('data', {}).get('alert', {}).get('severity', 'N/A')
                src_ip = alert_event.get('_source', {}).get('data', {}).get('src_ip', 'N/A')
                dest_ip = alert_event.get('_source', {}).get('data', {}).get('dest_ip', 'N/A')
                rule = alert_event.get('_source', {}).get('rule', {}).get('description', 'N/A')
                print(f"timestamp: {timestamp} level: {severity} src_ip: {src_ip} dest_ip: {dest_ip} rule: {rule}")
                
        except Exception as e:
            self.logger.error(f"Error fetching alert IDs: {e}")
            print(f"Error: {e}")
    
    def start_scheduler(self):
        """
        Start the scheduled data fetching
        """
        interval = self.config.get('scheduler', {}).get('interval_minutes', 5)
        
        self.logger.info(f"Starting Wazuh data fetcher with {interval}-minute interval")
        print(f"Wazuh Data Fetcher started - fetching every {interval} minutes")
        print("Press Ctrl+C to stop")
        
        # Schedule the job
        schedule.every(interval).minutes.do(self.fetch_and_print_ids)
        
        # Run the first fetch immediately
        self.fetch_and_print_ids()
        
        # Keep the scheduler running
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Scheduler stopped by user")
            print("\nScheduler stopped")
    
    def run_once(self):
        """
        Run the data fetch only once (for testing)
        """
        self.logger.info("Running single data fetch")
        self.fetch_and_print_ids()


def main():
    """
    Main entry point
    """
    try:
        # Ensure logs directory exists
        Path("logs").mkdir(exist_ok=True)
        
        # Initialize the fetcher
        fetcher = WazuhDataFetcher()
        
        # Check if we want to run once or continuously
        if len(sys.argv) > 1 and sys.argv[1] == "--once":
            fetcher.run_once()
        else:
            fetcher.start_scheduler()
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
