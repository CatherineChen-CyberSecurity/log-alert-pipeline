import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Dict, Any, List
import re

class EmailNotifier:
    def __init__(self, smtp_server: str, smtp_port: int, smtp_user: str, smtp_password: str, from_email: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.logger = logging.getLogger(__name__)

    def _get_nested_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """Get nested value from dictionary using dot notation."""
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

    def _replace_placeholders(self, template: str, data: Dict[str, Any]) -> str:
        """Replace placeholders like $(field_name) in the template."""
        
        def replacer(match):
            placeholder = match.group(1)
            # For aggregated alerts, the data is already flat
            if data.get('aggregation_summary'):
                value = data.get(placeholder, f"$({placeholder})")
            else:
                # For regular hits, we need to extract from _source
                value = self._get_nested_value(data.get('_source', {}), placeholder)
            
            if value is None:
                return f"$({placeholder})" # Keep placeholder if value not found
            
            return str(value)

        return re.sub(r'\$\((.*?)\)', replacer, template)

    def send_alert_email(self, recipient: str, template: str, hit: Dict[str, Any], rule: Dict[str, Any]):
        subject = f"Security Alert: {rule.get('rule_name', 'Unnamed Rule')}"
        
        # Replace placeholders in the template
        body = self._replace_placeholders(template, hit)
        
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, recipient, msg.as_string())
                self.logger.info(f"Successfully sent alert email to {recipient}")
        except Exception as e:
            self.logger.error(f"Failed to send email to {recipient}: {e}")
