#!/usr/bin/env python3
"""
Wazuh Data Fetcher - Scheduled data retrieval framework
This module provides a framework for fetching Wazuh alert data every 5 minutes
"""

import json
import schedule
import time
import yaml
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add the src directory to the Python path
sys.path.append(str(Path(__file__).parent))

from wazuh_client import WazuhClient
from log_parser import LogParser
from alert_analyzer import AlertAnalyzer


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
        self.analyzer = AlertAnalyzer()
        self.export_file = False
        self.export_file_name = "alert"
        self.export_file_path = "output"

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
    
    def process(self):
        """
        Fetch Wazuh alert data and process
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
            hits = self.parser.extract_hit_records(alerts)
            matched_alerts = self.analyzer.analyze_alert(hits)
            self.logger.info(f"Matched alerts: {matched_alerts}")

            # Export the data to a file
            if self.export_file:
                output_dir = Path(self.export_file_path)
                output_dir.mkdir(parents=True, exist_ok=True)
                file_path = output_dir / f"{self.export_file_name}.json"
                with open(file_path, 'w') as f:
                    json.dump(matched_alerts, f)
                self.logger.info(f"Exported alerts to {file_path}")
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
        schedule.every(interval).minutes.do(self.process)
        
        # Run the first fetch immediately
        self.process()
        
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
        self.process()

def main():
    """
    Main entry point
    """
    try:
        # Ensure logs directory exists
        Path("logs").mkdir(exist_ok=True)
        
        # Initialize the fetcher
        fetcher = WazuhDataFetcher()
        run_once = False
        
        # --help print the help message
        if len(sys.argv) > 1 and sys.argv[1] == "--help":
            print("Usage: python main.py [--once]")
            print("  --once: Run the data fetch only once")
            print("  --export: Export the data to a file")
            print("  --help: Print this help message")
            sys.exit(0)
        
        # --export export the data to a file
        if len(sys.argv) > 1 and sys.argv[1] == "--export":
            if len(sys.argv) > 2:
                fetcher.export_file_name = sys.argv[2]
            fetcher.export_file = True
            run_once = True
            
        # --once run the data fetch only once
        if len(sys.argv) > 1 and sys.argv[1] == "--once":
            run_once = True

        if run_once:
            fetcher.run_once()
        else:
            fetcher.start_scheduler()
            
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
