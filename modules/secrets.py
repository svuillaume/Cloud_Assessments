import re
import pandas as pd
from datetime import *


class Secrets:

    def __init__(self, raw_data):
        self.data = raw_data['data']

    def count_secrets(self):
        return len(self.data)

    @staticmethod
    def _permission_risk(path):
        if not isinstance(path, str) or not path:
            return '—'
        is_windows = '\\' in path or (len(path) > 2 and path[1] == ':')
        if is_windows:
            if 'AppData' in path or 'Users' in path:
                return 'Windows — restrict to owner account; remove Users/Everyone ACE'
            return 'Windows — verify Administrators/SYSTEM ACL only; no Users/Everyone ACE'
        # Linux / Unix
        if path.startswith('/etc/'):
            return 'Linux /etc — root:root 600 required; no world/group read'
        if path.startswith('/root/'):
            return 'Linux /root — root:root 600; accessible only by root'
        if path.startswith('/home/'):
            return 'Linux /home — owner:owner 600; no group or world permissions'
        if path.startswith('/var/'):
            return 'Linux /var — restrict to service account; chmod 640 minimum'
        if path.startswith('/tmp/'):
            return 'Linux /tmp — CRITICAL: world-readable directory; move immediately'
        if any(path.endswith(ext) for ext in ('.pem', '.key', '.p12', '.pfx', '.crt')):
            return 'Key/cert file — 600 (owner read-only); never world or group readable'
        return 'Linux/Unix — verify 600 (owner read-only); audit with: stat -c "%a %U %G" <path>'

    @staticmethod
    def _is_secure_default(path):
        """Return True when chmod 600 (owner read-only) is the strong default for this path.
        Secrets here are excluded from the CSP posture-score penalty."""
        if not isinstance(path, str) or not path:
            return False
        is_windows = '\\' in path or (len(path) > 2 and path[1] == ':')
        if is_windows:
            return False
        if path.startswith('/tmp/'):
            return False
        if path.startswith('/var/'):
            return False  # 640 minimum — not 600
        # All remaining Linux/Unix paths (including /etc/, /root/, /home/, key/cert
        # files, and the general fallback) carry a 600 recommendation.
        return True

    @staticmethod
    def _infer_csp(hostname):
        """Best-effort CSP inference from hostname naming conventions."""
        if not isinstance(hostname, str) or not hostname:
            return 'Unknown'
        h = hostname.lower()
        if (re.match(r'^ip-\d+', h) or re.match(r'^i-[0-9a-f]{8,17}$', h)
                or 'ec2' in h or 'aws' in h or 'amazon' in h):
            return 'AWS'
        if 'azure' in h or h.endswith('-vm') or 'azurevm' in h or 'msft' in h:
            return 'Azure'
        if 'gcp' in h or 'google' in h or re.match(r'^instance-[0-9]', h):
            return 'GCP'
        return 'Unknown'

    def risky_secrets_count(self):
        """Count secrets whose file paths are NOT in a chmod-600 secure-default location."""
        if not self.data:
            return 0
        return sum(
            1 for item in self.data
            if not self._is_secure_default(item.get('FILE_PATH', ''))
        )

    def legacy_rsa_count(self):
        """Count secrets using ssh-rsa (not rsa-sha2-256 or stronger)."""
        if not self.data:
            return 0
        return sum(
            1 for item in self.data
            if str(item.get('SSH_KEY_TYPE', '')).lower() == 'ssh-rsa'
        )

    def processed_secrets(self):
        df = pd.DataFrame(self.data)
        df.rename(
            columns={'HOSTNAME': 'Hostname', 'FILE_PATH': 'File Path', 'SSH_KEY_TYPE': 'SSH Key Type'},
            inplace=True)

        if 'Hostname' in df.columns:
            df.insert(1, 'CSP', df['Hostname'].apply(self._infer_csp))

        if 'File Path' in df.columns:
            df['Permission Risk'] = df['File Path'].apply(self._permission_risk)
            df['_secure'] = df['File Path'].apply(self._is_secure_default)
        else:
            df['_secure'] = False

        if 'SSH Key Type' in df.columns:
            df['Recommendation'] = df['SSH Key Type'].apply(
                lambda kt: 'Upgrade to ssh-ed25519 — stronger, faster, and immune to RSA timing attacks'
                if isinstance(kt, str) and 'rsa' in kt.lower() else '—'
            )

        return df

    def styled_secrets_html(self):
        """Return an HTML table coloured by key type: ssh-rsa=RED, rsa-sha2-256=GREEN."""
        df = self.processed_secrets()
        key_types = df['SSH Key Type'] if 'SSH Key Type' in df.columns else pd.Series([''] * len(df))
        display_df = df.drop(columns=['_secure'])

        def row_style(row):
            kt = str(key_types.iloc[row.name]).lower()
            if kt == 'ssh-rsa':
                return ['background-color:#FDECEA; color:#DA291C;'] * len(row)
            if kt in ('rsa-sha2-256', 'ssh-rsa256'):
                return ['background-color:#d4edda; color:#155724;'] * len(row)
            return [''] * len(row)

        return (
            display_df.style
            .apply(row_style, axis=1)
            .to_html(index=False)
        )
