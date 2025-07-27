import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Dict, Any, List, Tuple
import re

class EmailNotifier:
    def __init__(self, smtp_server: str, smtp_port: int, smtp_user: str, smtp_password: str, from_email: str, config: Dict[str, Any]):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.config = config 
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

    def _replace_placeholders(self, template: str, data: Dict[str, Any], context_data: Dict[str, Any]) -> str:
        """Replace placeholders like $(field_name) in the template."""
        
        def replacer(match):
            placeholder = match.group(1)

            # Check in context_data first (e.g., for rule_id, rule_score)
            value = context_data.get(placeholder)

            if value is None:
                # For aggregated alerts, the data is already flat
                if data.get('aggregation_summary'):
                    value = data.get(placeholder)
                else:
                    # For regular hits, we need to extract from _source
                    value = self._get_nested_value(data.get('_source', {}), f"data.{placeholder}")
            
            if value is None:
                return f"$({placeholder})"  # Keep placeholder if value not found
            if isinstance(value, list):
                return ', '.join(map(str, value))
            return str(value)

        return re.sub(r'\$\((.*?)\)', replacer, template)

    def send_alert_email(self, recipient: str, template: str, hit: Dict[str, Any], rule: Dict[str, Any]):
        subject = f"Security Alert: {rule.get('rule_name', 'Unnamed Rule')}"
        
        # Replace placeholders in the template, passing rule data as context
        body = self._replace_placeholders(template, hit, rule)
        
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
            
    def _send_email(self, recipient: str, subject: str, body: str, attachments: List[str] = None):
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Attach files if any
        if attachments:
            from email.mime.base import MIMEBase
            from email import encoders
            for file_path in attachments:
                try:
                    with open(file_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition', f'attachment; filename={file_path.split("/")[-1]}')
                        msg.attach(part)
                except Exception as e:
                    self.logger.error(f"Failed to attach file {file_path}: {e}")

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, recipient, msg.as_string())
                self.logger.info(f"Successfully sent summary email to {recipient}")
        except Exception as e:
            self.logger.error(f"Failed to send summary email to {recipient}: {e}")
            
    def send_summary_email(self, alerts: List[Tuple[Dict, Dict]], report_file: str):
        total_alerts = len(alerts)
        rule_hit_count = {}

        # Group alerts by rule_id
        rule_summary = {}
        for hit, rule in alerts:
            rule_id = str(rule.get('rule_id', 'unknown'))
            if rule_id not in rule_summary:
                rule_summary[rule_id] = {
                    'rule': rule,
                    'alerts': []
                }
            rule_summary[rule_id]['alerts'].append(hit)

        # For each rule, send summary email to configured recipient (fallback if not specified)
        for rule_id, data in rule_summary.items():
            rule = data['rule']
            matched_alerts = data['alerts']

            # Determine recipient email
            recipient = self.config.get('notification_email')
            for action in rule.get('rule_actions', []):
                if action.get('action') == 'email' and action.get('email'):
                    recipient = action.get('email')
                    break  # Found per-rule email, no need to fallback
            
            if not recipient:
                self.logger.warning(f"No email recipient defined for rule {rule_id}, skipping...")
                continue
            
            # Prepare email body using rule's template (only first alert for dynamic placeholders)
            template = ''
            for action in rule.get('rule_actions', []):
                if action.get('action') == 'email' and action.get('template'):
                    template = action.get('template')
                    break
            
            if matched_alerts:
                body = self._replace_placeholders(template, matched_alerts[0], rule)
            else:
                body = f"Rule {rule.get('rule_name')} triggered with {len(matched_alerts)} alerts."

            # Add total count info
            body += f"\n\nTotal Alerts: {len(matched_alerts)}"

            # Send email with CSV attachment
            self._send_email(
                recipient=recipient,
                subject=f"Alert Summary - {rule.get('rule_name', 'Unnamed Rule')}",
                body=body,
                attachments=[report_file]
            )