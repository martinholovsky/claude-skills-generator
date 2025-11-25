# Advanced Security Auditing Patterns

## Write-Once-Read-Many (WORM) Storage

### Implementing WORM for Audit Logs

```python
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone
import json

class WORMStorage:
    """
    Write-Once-Read-Many storage for audit logs.

    Once written, entries cannot be modified or deleted.
    Uses append-only files with integrity verification.
    """

    def __init__(self, base_path: str, signing_key: bytes):
        self._base_path = Path(base_path)
        self._signing_key = signing_key
        self._base_path.mkdir(parents=True, exist_ok=True)

    def _get_log_path(self, date: datetime = None) -> Path:
        """Get log file path for date (one file per day)."""
        if date is None:
            date = datetime.now(timezone.utc)
        return self._base_path / f"audit-{date.strftime('%Y-%m-%d')}.log"

    def _get_index_path(self, log_path: Path) -> Path:
        """Get index file for log."""
        return log_path.with_suffix('.index')

    def write(self, entry: dict) -> str:
        """
        Write entry to WORM storage.

        Returns:
            Entry ID for retrieval
        """
        log_path = self._get_log_path()
        index_path = self._get_index_path(log_path)

        # Serialize entry
        entry['timestamp'] = datetime.now(timezone.utc).isoformat()
        entry_json = json.dumps(entry, sort_keys=True)
        entry_bytes = entry_json.encode('utf-8')

        # Calculate hash
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()

        # Open in append mode only
        with open(log_path, 'ab') as f:
            offset = f.tell()
            f.write(entry_bytes + b'\n')

        # Write to index
        with open(index_path, 'a') as f:
            f.write(f"{entry_hash},{offset},{len(entry_bytes)}\n")

        # Make files immutable (requires root)
        self._make_immutable(log_path)

        return entry_hash

    def _make_immutable(self, path: Path):
        """Make file append-only using chattr."""
        try:
            import subprocess
            subprocess.run(
                ['chattr', '+a', str(path)],
                capture_output=True,
                check=False  # May fail without root
            )
        except FileNotFoundError:
            pass  # chattr not available

    def read(self, entry_id: str) -> dict:
        """Read entry by ID (hash)."""
        # Search all index files
        for index_path in self._base_path.glob('*.index'):
            with open(index_path) as f:
                for line in f:
                    hash_val, offset, length = line.strip().split(',')
                    if hash_val == entry_id:
                        log_path = index_path.with_suffix('.log')
                        with open(log_path, 'rb') as lf:
                            lf.seek(int(offset))
                            data = lf.read(int(length))
                            return json.loads(data)

        raise KeyError(f"Entry not found: {entry_id}")

    def verify_integrity(self) -> tuple[bool, list]:
        """Verify integrity of all logs."""
        errors = []

        for log_path in self._base_path.glob('*.log'):
            index_path = self._get_index_path(log_path)

            if not index_path.exists():
                errors.append(f"Missing index: {index_path}")
                continue

            with open(index_path) as idx, open(log_path, 'rb') as log:
                for line_num, line in enumerate(idx, 1):
                    hash_val, offset, length = line.strip().split(',')

                    log.seek(int(offset))
                    data = log.read(int(length))
                    actual_hash = hashlib.sha256(data).hexdigest()

                    if actual_hash != hash_val:
                        errors.append(
                            f"{log_path}:{line_num}: Hash mismatch"
                        )

        return len(errors) == 0, errors
```

## Merkle Tree Audit Log

```python
import hashlib
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class MerkleNode:
    """Node in Merkle tree."""
    hash: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    data: Optional[bytes] = None


class MerkleAuditLog:
    """
    Audit log using Merkle tree for efficient integrity verification.

    Allows proving individual entry inclusion without
    reading entire log.
    """

    def __init__(self):
        self._entries: List[bytes] = []
        self._tree: Optional[MerkleNode] = None

    def add_entry(self, entry: dict) -> int:
        """Add entry and rebuild tree."""
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        self._entries.append(entry_bytes)
        self._tree = self._build_tree(self._entries)
        return len(self._entries) - 1

    def _build_tree(self, entries: List[bytes]) -> MerkleNode:
        """Build Merkle tree from entries."""
        if not entries:
            return MerkleNode(hash=hashlib.sha256(b'').hexdigest())

        # Create leaf nodes
        nodes = [
            MerkleNode(
                hash=hashlib.sha256(entry).hexdigest(),
                data=entry
            )
            for entry in entries
        ]

        # Build tree bottom-up
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left

                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()

                new_level.append(MerkleNode(
                    hash=parent_hash,
                    left=left,
                    right=right
                ))
            nodes = new_level

        return nodes[0]

    def get_root_hash(self) -> str:
        """Get Merkle root hash."""
        return self._tree.hash if self._tree else ''

    def get_proof(self, index: int) -> List[tuple]:
        """
        Get Merkle proof for entry at index.

        Returns list of (hash, position) tuples.
        """
        if index >= len(self._entries):
            raise IndexError(f"Entry {index} not found")

        proof = []
        nodes = [
            MerkleNode(hash=hashlib.sha256(e).hexdigest())
            for e in self._entries
        ]

        idx = index
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left

                if i == idx or i + 1 == idx:
                    sibling = right if i == idx else left
                    position = 'right' if i == idx else 'left'
                    proof.append((sibling.hash, position))

                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                new_level.append(MerkleNode(hash=parent_hash))

            idx = idx // 2
            nodes = new_level

        return proof

    def verify_proof(self, entry: bytes, proof: List[tuple], root: str) -> bool:
        """Verify Merkle proof."""
        current_hash = hashlib.sha256(entry).hexdigest()

        for sibling_hash, position in proof:
            if position == 'right':
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash

            current_hash = hashlib.sha256(combined.encode()).hexdigest()

        return current_hash == root
```

## Real-Time Anomaly Detection

```python
from collections import defaultdict
from datetime import datetime, timedelta
import statistics

class AnomalyDetector:
    """Detect anomalies in audit events."""

    def __init__(self):
        self._baselines = {}
        self._recent_events = defaultdict(list)
        self._window = timedelta(minutes=5)

    def record_event(self, event_type: str, user_id: str, timestamp: datetime = None):
        """Record event for baseline calculation."""
        if timestamp is None:
            timestamp = datetime.now()

        key = (event_type, user_id)
        self._recent_events[key].append(timestamp)

        # Clean old events
        cutoff = timestamp - self._window
        self._recent_events[key] = [
            t for t in self._recent_events[key] if t > cutoff
        ]

    def check_rate_anomaly(
        self,
        event_type: str,
        user_id: str,
        threshold_multiplier: float = 3.0
    ) -> tuple[bool, dict]:
        """
        Check if event rate is anomalous.

        Returns:
            Tuple of (is_anomaly, details)
        """
        key = (event_type, user_id)
        current_count = len(self._recent_events.get(key, []))

        # Get baseline
        baseline_key = f"{event_type}_baseline"
        if baseline_key not in self._baselines:
            return False, {'reason': 'No baseline'}

        baseline = self._baselines[baseline_key]
        threshold = baseline['mean'] + (baseline['stddev'] * threshold_multiplier)

        is_anomaly = current_count > threshold

        return is_anomaly, {
            'current_count': current_count,
            'baseline_mean': baseline['mean'],
            'baseline_stddev': baseline['stddev'],
            'threshold': threshold,
            'event_type': event_type,
            'user_id': user_id
        }

    def update_baseline(self, event_type: str, counts: list):
        """Update baseline for event type."""
        if not counts:
            return

        self._baselines[f"{event_type}_baseline"] = {
            'mean': statistics.mean(counts),
            'stddev': statistics.stdev(counts) if len(counts) > 1 else 0,
            'updated': datetime.now().isoformat()
        }

    def detect_impossible_travel(
        self,
        user_id: str,
        locations: list,
        max_speed_kmh: float = 900
    ) -> tuple[bool, dict]:
        """
        Detect impossible travel (login from distant locations).

        Args:
            user_id: User identifier
            locations: List of (timestamp, lat, lon) tuples
            max_speed_kmh: Maximum possible travel speed

        Returns:
            Tuple of (is_anomaly, details)
        """
        if len(locations) < 2:
            return False, {}

        from math import radians, cos, sin, asin, sqrt

        def haversine(lat1, lon1, lat2, lon2):
            """Calculate distance between two points in km."""
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            return 2 * asin(sqrt(a)) * 6371

        for i in range(len(locations) - 1):
            t1, lat1, lon1 = locations[i]
            t2, lat2, lon2 = locations[i + 1]

            distance = haversine(lat1, lon1, lat2, lon2)
            time_hours = (t2 - t1).total_seconds() / 3600

            if time_hours > 0:
                speed = distance / time_hours
                if speed > max_speed_kmh:
                    return True, {
                        'user_id': user_id,
                        'distance_km': distance,
                        'time_hours': time_hours,
                        'speed_kmh': speed,
                        'location1': (lat1, lon1),
                        'location2': (lat2, lon2)
                    }

        return False, {}
```

## Compliance Report Generation

```python
from datetime import datetime, timedelta
from typing import List, Dict
import json

class ComplianceReporter:
    """Generate compliance reports from audit logs."""

    def __init__(self, log_reader):
        self._reader = log_reader

    def generate_access_report(
        self,
        start_date: datetime,
        end_date: datetime,
        resource_type: str = None
    ) -> Dict:
        """
        Generate data access report for compliance.

        Required by: GDPR Art 30, HIPAA 164.312(b), PCI-DSS 10
        """
        events = self._reader.query(
            event_type='data.access',
            start_date=start_date,
            end_date=end_date
        )

        if resource_type:
            events = [e for e in events if e.get('resource_type') == resource_type]

        # Aggregate by user
        by_user = {}
        for event in events:
            user = event.get('user_id', 'unknown')
            if user not in by_user:
                by_user[user] = {'read': 0, 'write': 0, 'delete': 0}
            action = event.get('action', 'read')
            by_user[user][action] = by_user[user].get(action, 0) + 1

        return {
            'report_type': 'data_access',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_events': len(events),
            'unique_users': len(by_user),
            'by_user': by_user,
            'generated': datetime.utcnow().isoformat()
        }

    def generate_authentication_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """
        Generate authentication report.

        Shows login attempts, failures, MFA usage.
        """
        events = self._reader.query(
            event_type='auth.attempt',
            start_date=start_date,
            end_date=end_date
        )

        successful = [e for e in events if e.get('success')]
        failed = [e for e in events if not e.get('success')]

        # Group failures by reason
        failure_reasons = {}
        for event in failed:
            reason = event.get('failure_reason', 'unknown')
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

        # Find users with excessive failures
        user_failures = {}
        for event in failed:
            user = event.get('user_id', 'unknown')
            user_failures[user] = user_failures.get(user, 0) + 1

        high_failure_users = {
            u: c for u, c in user_failures.items() if c > 5
        }

        return {
            'report_type': 'authentication',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_attempts': len(events),
            'successful': len(successful),
            'failed': len(failed),
            'failure_rate': len(failed) / len(events) if events else 0,
            'failure_reasons': failure_reasons,
            'high_failure_users': high_failure_users,
            'generated': datetime.utcnow().isoformat()
        }

    def generate_privileged_access_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """
        Generate privileged access report.

        Required by: SOC2 CC6.1, ISO 27001 A.9.2.3
        """
        events = self._reader.query(
            event_type='authz.decision',
            start_date=start_date,
            end_date=end_date
        )

        # Filter for admin/privileged access
        privileged = [
            e for e in events
            if 'admin' in e.get('resource', '').lower()
            or e.get('action') in ['delete', 'modify_config', 'grant_permission']
        ]

        return {
            'report_type': 'privileged_access',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_privileged_operations': len(privileged),
            'by_user': self._group_by_user(privileged),
            'by_resource': self._group_by(privileged, 'resource'),
            'by_action': self._group_by(privileged, 'action'),
            'generated': datetime.utcnow().isoformat()
        }

    def _group_by(self, events: List, field: str) -> Dict:
        """Group events by field."""
        result = {}
        for event in events:
            key = event.get(field, 'unknown')
            result[key] = result.get(key, 0) + 1
        return result

    def _group_by_user(self, events: List) -> Dict:
        """Group events by user."""
        return self._group_by(events, 'user_id')
```
