import pandas as pd
from logzero import logger
from datetime import *


class IdentityEntitlements:

    def __init__(self, raw_data):
        self.data = raw_data['data']

    def _process_data(self):
        """
        Process raw LQL data into a pandas DataFrame with calculated fields
        """
        if not self.data:
            return pd.DataFrame()

        processed_data = []
        for item in self.data:
            # Extract entitlement counts - use correct field names from Lacework
            entitlement_counts = item.get('ENTITLEMENT_COUNTS', {})
            used_count = entitlement_counts.get('entitlements_used_count', 0)
            unused_count = entitlement_counts.get('entitlements_unused_count', 0)
            total_count = entitlement_counts.get('entitlements_total_count', used_count + unused_count)

            # Calculate unused percentage
            unused_percentage = 0
            if total_count > 0:
                unused_percentage = round((unused_count / total_count) * 100, 1)

            # Extract risk metrics
            metrics = item.get('METRICS', {})
            risks = metrics.get('risks', []) if metrics else []
            risk_severity = metrics.get('risk_severity', 'UNKNOWN') if metrics else 'UNKNOWN'

            # Check if this is a root/admin identity
            has_full_admin = 'ALLOWS_FULL_ADMIN' in risks

            # Check MFA status from risks
            # PASSWORD_LOGIN_NO_MFA indicates user has password login enabled without MFA
            has_mfa_disabled = 'PASSWORD_LOGIN_NO_MFA' in risks
            mfa_status = 'Disabled' if has_mfa_disabled else 'Enabled'

            processed_data.append({
                'RECORD_CREATED_TIME': item.get('RECORD_CREATED_TIME', ''),
                'PRINCIPAL_ID': item.get('PRINCIPAL_ID', ''),
                'NAME': item.get('NAME', ''),
                'PROVIDER_TYPE': item.get('PROVIDER_TYPE', ''),
                'DOMAIN_ID': item.get('DOMAIN_ID', ''),
                'LAST_USED_TIME': item.get('LAST_USED_TIME', ''),
                'CREATED_TIME': item.get('CREATED_TIME', ''),
                'used_count': used_count,
                'unused_count': unused_count,
                'total_count': total_count,
                'unused_percentage': unused_percentage,
                'risks': risks,
                'risk_severity': risk_severity,
                'has_full_admin': has_full_admin,
                'mfa_status': mfa_status,
                'has_mfa_disabled': has_mfa_disabled
            })

        return pd.DataFrame(processed_data)

    def get_high_privilege_identities(self, threshold=70):
        """
        Get identities with unused entitlements >= threshold COUNT (not percentage)

        Args:
            threshold: Minimum unused entitlement COUNT (default 70)

        Returns:
            pandas DataFrame of identities meeting criteria
        """
        df = self._process_data()
        if df.empty:
            return df

        # Filter by unused COUNT threshold (matching original ciem.sh behavior)
        high_priv = df[df['unused_count'] >= threshold]

        # Sort by unused count descending
        high_priv = high_priv.sort_values(by='unused_count', ascending=False)

        return high_priv

    def get_root_identities(self):
        """
        Get identities with ALLOWS_FULL_ADMIN risk

        Returns:
            pandas DataFrame of root/admin identities
        """
        df = self._process_data()
        if df.empty:
            return df

        # Filter by full admin access
        root = df[df['has_full_admin'] == True]

        # Sort by risk severity and unused percentage
        root = root.sort_values(by=['risk_severity', 'unused_percentage'], ascending=[False, False])

        return root

    def get_critical_identities(self, threshold=70):
        """
        Get identities that are BOTH root/admin AND have high unused entitlements
        This represents the highest risk identities

        Args:
            threshold: Minimum unused entitlement COUNT (default 70)

        Returns:
            pandas DataFrame of critical risk identities
        """
        df = self._process_data()
        if df.empty:
            return df

        # Filter by both criteria: full admin AND high unused COUNT
        critical = df[(df['has_full_admin'] == True) & (df['unused_count'] >= threshold)]

        # Sort by unused count descending
        critical = critical.sort_values(by='unused_count', ascending=False)

        return critical

    def get_summary_counts(self, threshold=70):
        """
        Get summary statistics for template

        Args:
            threshold: Minimum unused entitlement COUNT (default 70)

        Returns:
            Dictionary with count statistics
        """
        df = self._process_data()
        if df.empty:
            return {
                'total_count': 0,
                'high_privilege_count': 0,
                'root_count': 0,
                'critical_count': 0,
                'threshold': threshold
            }

        return {
            'total_count': len(df),
            'high_privilege_count': len(df[df['unused_count'] >= threshold]),
            'root_count': len(df[df['has_full_admin'] == True]),
            'critical_count': len(df[(df['has_full_admin'] == True) & (df['unused_count'] >= threshold)]),
            'threshold': threshold
        }

    def count_identities(self):
        """
        Get total count of identities

        Returns:
            Integer count
        """
        return len(self.data)

    def get_all_identities(self, limit=25):
        """
        Get all identities sorted by unused percentage (highest first)

        Args:
            limit: Maximum number of identities to return (default 25)

        Returns:
            pandas DataFrame of identities
        """
        df = self._process_data()
        if df.empty:
            return df

        # Sort by unused percentage descending, then by has_full_admin
        df = df.sort_values(by=['has_full_admin', 'unused_percentage'], ascending=[False, False])

        return df.head(limit)
