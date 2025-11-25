# Security Auditing Examples

## Complete SIEM Integration

### Splunk HTTP Event Collector

```python
"""
Splunk HEC integration for JARVIS audit logs.
"""

import requests
import json
import logging
from typing import Optional, Dict
from datetime import datetime
import queue
import threading

logger = logging.getLogger(__name__)


class SplunkHECForwarder:
    """
    Forward events to Splunk HTTP Event Collector.

    Features:
    - Batching for efficiency
    - Retry logic
    - TLS verification
    """

    def __init__(
        self,
        url: str,
        token: str,
        index: str = 'main',
        source: str = 'jarvis',
        sourcetype: str = 'jarvis:audit',
        batch_size: int = 100,
        flush_interval: int = 5
    ):
        self._url = url
        self._token = token
        self._index = index
        self._source = source
        self._sourcetype = sourcetype
        self._batch_size = batch_size
        self._flush_interval = flush_interval

        self._queue = queue.Queue()
        self._batch = []
        self._running = False

        self._session = requests.Session()
        self._session.headers.update({
            'Authorization': f'Splunk {token}',
            'Content-Type': 'application/json'
        })

    def start(self):
        """Start background sender thread."""
        self._running = True
        self._thread = threading.Thread(target=self._sender_loop)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        """Stop and flush remaining events."""
        self._running = False
        self._flush()
        self._thread.join(timeout=5)

    def send(self, event: Dict):
        """Queue event for sending."""
        self._queue.put(event)

    def _sender_loop(self):
        """Background loop to batch and send events."""
        import time

        last_flush = time.time()

        while self._running:
            try:
                # Get events from queue
                try:
                    event = self._queue.get(timeout=1)
                    self._batch.append(event)
                except queue.Empty:
                    pass

                # Flush if batch full or interval elapsed
                if (len(self._batch) >= self._batch_size or
                    time.time() - last_flush >= self._flush_interval):
                    self._flush()
                    last_flush = time.time()

            except Exception as e:
                logger.error(f"SIEM sender error: {e}")

    def _flush(self):
        """Send batched events to Splunk."""
        if not self._batch:
            return

        payload = ''
        for event in self._batch:
            splunk_event = {
                'event': event,
                'time': datetime.utcnow().timestamp(),
                'index': self._index,
                'source': self._source,
                'sourcetype': self._sourcetype
            }
            payload += json.dumps(splunk_event)

        try:
            response = self._session.post(
                self._url,
                data=payload,
                timeout=10,
                verify=True
            )
            response.raise_for_status()

            logger.debug(f"Sent {len(self._batch)} events to Splunk")
            self._batch = []

        except requests.RequestException as e:
            logger.error(f"Failed to send to Splunk: {e}")
            # Keep batch for retry


# Usage example
def setup_splunk_integration():
    forwarder = SplunkHECForwarder(
        url='https://splunk.example.com:8088/services/collector/event',
        token='your-hec-token',
        index='jarvis_audit',
        sourcetype='jarvis:audit'
    )
    forwarder.start()
    return forwarder
```

### Elasticsearch/OpenSearch Integration

```python
"""
Elasticsearch integration for audit log storage and search.
"""

from elasticsearch import Elasticsearch, helpers
from datetime import datetime
from typing import List, Dict
import json


class ElasticsearchAuditStore:
    """Store and query audit logs in Elasticsearch."""

    def __init__(
        self,
        hosts: List[str],
        index_prefix: str = 'jarvis-audit',
        api_key: str = None
    ):
        self._es = Elasticsearch(
            hosts=hosts,
            api_key=api_key,
            verify_certs=True
        )
        self._index_prefix = index_prefix
        self._ensure_template()

    def _ensure_template(self):
        """Create index template for audit logs."""
        template = {
            'index_patterns': [f'{self._index_prefix}-*'],
            'template': {
                'settings': {
                    'number_of_shards': 1,
                    'number_of_replicas': 1,
                    'index.lifecycle.name': 'audit-retention',
                },
                'mappings': {
                    'properties': {
                        'timestamp': {'type': 'date'},
                        'event_type': {'type': 'keyword'},
                        'level': {'type': 'keyword'},
                        'user_id': {'type': 'keyword'},
                        'ip_address': {'type': 'ip'},
                        'resource': {'type': 'keyword'},
                        'action': {'type': 'keyword'},
                        'outcome': {'type': 'keyword'},
                        'context': {'type': 'object'},
                        'hash': {'type': 'keyword'},
                        'signature': {'type': 'keyword'}
                    }
                }
            }
        }

        self._es.indices.put_index_template(
            name=f'{self._index_prefix}-template',
            body=template
        )

    def _get_index_name(self, date: datetime = None) -> str:
        """Get index name for date (daily indices)."""
        if date is None:
            date = datetime.utcnow()
        return f"{self._index_prefix}-{date.strftime('%Y.%m.%d')}"

    def store(self, event: Dict):
        """Store single event."""
        self._es.index(
            index=self._get_index_name(),
            body=event
        )

    def bulk_store(self, events: List[Dict]):
        """Bulk store events."""
        actions = [
            {
                '_index': self._get_index_name(),
                '_source': event
            }
            for event in events
        ]

        helpers.bulk(self._es, actions)

    def search(
        self,
        query: Dict = None,
        start_date: datetime = None,
        end_date: datetime = None,
        size: int = 100
    ) -> List[Dict]:
        """Search audit logs."""
        must = []

        if start_date or end_date:
            range_query = {'timestamp': {}}
            if start_date:
                range_query['timestamp']['gte'] = start_date.isoformat()
            if end_date:
                range_query['timestamp']['lte'] = end_date.isoformat()
            must.append({'range': range_query})

        if query:
            must.append(query)

        body = {
            'query': {'bool': {'must': must}} if must else {'match_all': {}},
            'size': size,
            'sort': [{'timestamp': 'desc'}]
        }

        result = self._es.search(
            index=f'{self._index_prefix}-*',
            body=body
        )

        return [hit['_source'] for hit in result['hits']['hits']]

    def get_user_activity(self, user_id: str, days: int = 30) -> List[Dict]:
        """Get all activity for a user."""
        return self.search(
            query={'term': {'user_id': user_id}},
            start_date=datetime.utcnow() - timedelta(days=days)
        )
```

## Falco Rules for Runtime Detection

```yaml
# /etc/falco/jarvis_rules.yaml
# Runtime security detection for JARVIS

- rule: JARVIS Credential Access Attempt
  desc: Detect attempts to access JARVIS credential stores
  condition: >
    open_read and
    (fd.name contains "/jarvis/" or fd.name contains ".jarvis") and
    (fd.name contains "credential" or fd.name contains "secret" or fd.name contains "key")
  output: >
    Credential file access (user=%user.name user_loginuid=%user.loginuid
    command=%proc.cmdline file=%fd.name container_id=%container.id)
  priority: WARNING
  tags: [credential_access, jarvis]

- rule: JARVIS Database Tampering
  desc: Detect modification of JARVIS database files
  condition: >
    open_write and
    fd.name contains "/jarvis/" and
    fd.name endswith ".db"
  output: >
    Database file modified (user=%user.name command=%proc.cmdline
    file=%fd.name container_id=%container.id)
  priority: ERROR
  tags: [database, integrity, jarvis]

- rule: JARVIS Log Deletion
  desc: Detect deletion of JARVIS audit logs
  condition: >
    (evt.type = unlink or evt.type = unlinkat) and
    fd.name contains "/var/log/jarvis"
  output: >
    Audit log deleted (user=%user.name command=%proc.cmdline
    file=%fd.name container_id=%container.id)
  priority: CRITICAL
  tags: [log_tampering, jarvis]

- rule: JARVIS Privilege Escalation Attempt
  desc: Detect privilege escalation in JARVIS containers
  condition: >
    spawned_process and
    container.name contains "jarvis" and
    (proc.name = "sudo" or proc.name = "su" or proc.name = "pkexec")
  output: >
    Privilege escalation attempt (user=%user.name command=%proc.cmdline
    container=%container.name)
  priority: CRITICAL
  tags: [privilege_escalation, jarvis]

- rule: JARVIS Network Exfiltration
  desc: Detect unusual outbound connections from JARVIS
  condition: >
    outbound and
    container.name contains "jarvis" and
    not (fd.sip = "127.0.0.1" or fd.sip in (allowed_ips))
  output: >
    Unexpected outbound connection (user=%user.name command=%proc.cmdline
    connection=%fd.name container=%container.name)
  priority: WARNING
  tags: [exfiltration, jarvis]
```

## Complete Audit Trail Implementation

```python
"""
Complete audit trail system for JARVIS.
"""

import structlog
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from contextlib import contextmanager
import threading

# Thread-local storage for correlation ID
_context = threading.local()


def set_correlation_id(correlation_id: str):
    """Set correlation ID for current request."""
    _context.correlation_id = correlation_id


def get_correlation_id() -> str:
    """Get correlation ID for current request."""
    return getattr(_context, 'correlation_id', 'unknown')


class AuditTrail:
    """
    Complete audit trail system with integrity protection.

    Features:
    - Tamper-evident logging
    - Automatic correlation
    - Compliance-ready output
    - SIEM forwarding
    """

    def __init__(
        self,
        log_path: str,
        signing_key: bytes,
        siem_forwarder=None
    ):
        self._log_path = Path(log_path)
        self._signing_key = signing_key
        self._siem = siem_forwarder
        self._sequence = 0
        self._previous_hash = b'\x00' * 32
        self._lock = threading.Lock()

        # Ensure directory exists
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer()
            ]
        )

        self._logger = structlog.get_logger()

    @contextmanager
    def request_context(self, correlation_id: str = None):
        """Context manager for request-scoped audit."""
        if correlation_id is None:
            correlation_id = os.urandom(16).hex()

        set_correlation_id(correlation_id)
        try:
            yield correlation_id
        finally:
            pass  # Cleanup if needed

    def log_security_event(
        self,
        event_type: str,
        severity: str,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        outcome: str = 'success',
        **context
    ) -> Dict[str, Any]:
        """
        Log a security event with full audit trail.

        Args:
            event_type: Event identifier
            severity: DEBUG/INFO/WARNING/ERROR/CRITICAL
            actor: Who performed the action
            resource: What was affected
            action: What was done
            outcome: success/failure
            **context: Additional context

        Returns:
            Complete audit entry
        """
        with self._lock:
            self._sequence += 1

            entry = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'sequence': self._sequence,
                'correlation_id': get_correlation_id(),
                'event_type': event_type,
                'severity': severity,
                'actor': actor,
                'resource': resource,
                'action': action,
                'outcome': outcome,
                'context': context,
                'previous_hash': self._previous_hash.hex(),
            }

            # Calculate integrity values
            entry_bytes = json.dumps(entry, sort_keys=True).encode()
            entry_hash = hashlib.sha256(entry_bytes).digest()
            signature = hmac.new(
                self._signing_key,
                entry_bytes,
                hashlib.sha256
            ).hexdigest()

            entry['hash'] = entry_hash.hex()
            entry['signature'] = signature

            # Update chain
            self._previous_hash = entry_hash

            # Write to log file
            with open(self._log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')

            # Forward to SIEM
            if self._siem:
                self._siem.send(entry)

            # Also log via structlog for console/other handlers
            log_method = getattr(self._logger, severity.lower(), self._logger.info)
            log_method(event_type, **{
                k: v for k, v in entry.items()
                if k not in ['previous_hash', 'hash', 'signature']
            })

            return entry

    def log_authentication(
        self,
        user_id: str,
        success: bool,
        method: str,
        ip_address: str,
        **kwargs
    ):
        """Log authentication attempt."""
        return self.log_security_event(
            event_type='auth.attempt',
            severity='INFO' if success else 'WARNING',
            actor=user_id,
            action='authenticate',
            outcome='success' if success else 'failure',
            method=method,
            ip_address=ip_address,
            **kwargs
        )

    def log_authorization(
        self,
        user_id: str,
        resource: str,
        action: str,
        allowed: bool,
        **kwargs
    ):
        """Log authorization decision."""
        return self.log_security_event(
            event_type='authz.decision',
            severity='INFO' if allowed else 'WARNING',
            actor=user_id,
            resource=resource,
            action=action,
            outcome='allowed' if allowed else 'denied',
            **kwargs
        )

    def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        **kwargs
    ):
        """Log data access for compliance."""
        return self.log_security_event(
            event_type='data.access',
            severity='INFO',
            actor=user_id,
            resource=f"{resource_type}/{resource_id}",
            action=action,
            outcome='success',
            **kwargs
        )

    def log_configuration_change(
        self,
        user_id: str,
        config_item: str,
        old_value: str,
        new_value: str,
        **kwargs
    ):
        """Log configuration changes."""
        return self.log_security_event(
            event_type='config.change',
            severity='WARNING',
            actor=user_id,
            resource=config_item,
            action='modify',
            outcome='success',
            old_value=old_value,
            new_value=new_value,
            **kwargs
        )


# Usage example
def example_usage():
    signing_key = os.urandom(32)

    audit = AuditTrail(
        log_path='/var/log/jarvis/audit.log',
        signing_key=signing_key
    )

    with audit.request_context() as correlation_id:
        # Log authentication
        audit.log_authentication(
            user_id='user123',
            success=True,
            method='password',
            ip_address='192.168.1.100'
        )

        # Log authorization
        audit.log_authorization(
            user_id='user123',
            resource='/api/secrets',
            action='read',
            allowed=True
        )

        # Log data access
        audit.log_data_access(
            user_id='user123',
            resource_type='secret',
            resource_id='api-key-1',
            action='read'
        )
```
