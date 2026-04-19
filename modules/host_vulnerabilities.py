import pandas as pd
import plotly.graph_objects as go
from logzero import logger
import json
from modules.chart_utils import render_bubbles, render_host_priority


class HostVulnerabilities:

    def __init__(self, raw_data):
        # Filter all vulnerabilities to riskScore >= 9.0
        self.data = self._filter_by_risk_score(raw_data)

    def _filter_by_risk_score(self, raw_data, min_score=9.0):
        """Filter vulnerabilities: keep only those with riskScore >= min_score.

        Args:
            raw_data: List of vulnerability records
            min_score: Minimum FortiCNAPP CVE Risk Score threshold (default 9.0)

        Returns:
            Filtered list of vulnerabilities
        """
        filtered_data = []
        for vuln in raw_data:
            cve_risk_score = vuln.get('riskScore')
            if cve_risk_score is not None and float(cve_risk_score) >= min_score:
                filtered_data.append(vuln)

        logger.info(f'Filtered host vulnerabilities: {len(raw_data)} -> {len(filtered_data)} (riskScore >= {min_score})')
        return filtered_data

    def total_evaluated(self):
        df = pd.DataFrame(self.data)
        # count severities by host & total sum
        unique_hosts = df.mid.nunique()
        return unique_hosts

    def summary_by_host(self, severities=("Critical", "High", "Medium", "Low"), limit=False):
        df = pd.json_normalize(self.data,
                               meta=[['cveProps', 'metadata'], ['evalCtx', 'hostname'], ['featureKey', 'name'],
                                     'vulnId', 'severity', 'mid'])

        if 'severity' not in df:
            df['severity'] = False

        # filter
        df = df[df['severity'].isin(severities)]

        # delete extra columns
        df = df[['evalCtx.hostname', 'mid', 'severity']]

        # count severities by MID
        df = df.groupby(['mid', 'severity', 'evalCtx.hostname']).size().reset_index(name='count')

        # summarize severities onto one column (and sort)
        df['sev_merged'] = df['severity'].astype('string') + ": " + df['count'].astype('string')
        df['severity'] = pd.Categorical(df['severity'], ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['severity', 'count'], ascending=[True, False])
        df = df.groupby('mid', sort=False, as_index=False).agg(
            {'mid': 'first', 'evalCtx.hostname': 'first', 'sev_merged': f"\n".join})

        # clean names
        df.rename(columns={'mid': 'Machine ID', 'evalCtx.hostname': 'Hostname', 'sev_merged': 'Severity Count'},
                  inplace=True)
        df = df.drop(columns=['Machine ID'])

        if limit:
            df = df.head(limit)
        return df

    def fixable_vulns(self, severities=("Critical", "High"), limit=False):
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'],
                                     ['featureKey', 'name'],
                                     'vulnId',
                                     'severity',
                                     ['fixInfo', 'fix_available'],
                                     ['fixInfo', 'fixed_version'],
                                     ['featureKey', 'version_installed']])
        if 'severity' not in df:
            df['severity'] = False
        df = df[df['severity'].isin(severities)]
        df = df[df['fixInfo.fix_available'] == '1']
        if not df.empty:
            #cve_count = df.groupby('evalCtx.hostname')['vulnId'].nunique()
            #print(cve_count)
            df = df[['evalCtx.hostname', 'severity', 'vulnId', 'featureKey.name', 'featureKey.version_installed', 'fixInfo.fixed_version']]
            # df = df.groupby(['evalCtx.hostname', 'featureKey.name', 'featureKey.version_installed', 'severity', 'vulnId'],
            #                 as_index=False).agg({'fixInfo.fixed_version': ', '.join})
            df = df.groupby(['evalCtx.hostname', 'severity', 'vulnId', 'featureKey.name', 'featureKey.version_installed'],
                            as_index=False).agg(lambda x: ', '.join(x.unique()) if x.dtype == 'object' else x.iloc[0])
            df = df.groupby(['evalCtx.hostname', 'severity', 'featureKey.name', 'fixInfo.fixed_version','featureKey.version_installed' ], as_index=False).agg({'vulnId': ', '.join})
            # rename columns
            df.rename(columns={'evalCtx.hostname': 'Hostname',
                               'severity': 'Severity',
                               'vulnId': 'CVE',
                               'featureKey.name': 'Package Name',
                               "fixInfo.fixed_version": "Fixed Version(s)",
                               'featureKey.version_installed': "Installed Version"},
                      inplace=True)
            df = df[['Hostname', 'CVE', 'Severity', 'Package Name', 'Installed Version', 'Fixed Version(s)']]
        return df

    def summary(self, severities=("Critical", "High", "Medium", "Low")):
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'], ['featureKey', 'name'], 'vulnId', 'severity', 'mid'])

        if 'severity' not in df:
            df['severity'] = False

        # filter
        df = df[df['severity'].isin(severities)]

        # delete extra columns
        df = df[['evalCtx.hostname', 'mid', 'severity']]

        # count severities by host & total sum
        df = df.groupby(['severity'], as_index=False)['mid'].agg(['count', 'nunique'])

        for severity in severities:
            if not severity in df.index: df = pd.concat(
                [df, pd.DataFrame([{'severity': severity, 'count': 0, 'nunique': 0}]).set_index('severity')])

        df = df.reset_index()

        # sort
        df['severity'] = pd.Categorical(df['severity'], ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['severity'])
        df = df.reset_index()
        df = df.drop(columns=['index'])

        # rename columns
        df.rename(columns={'severity': 'Severity', 'count': 'Total CVEs', 'nunique': 'Hosts Affected'}, inplace=True)

        return df

    def all_cves_detail(self, severities=("High", "Medium", "Low"), limit=100):
        """Get detailed CVE information for specified severities.

        Args:
            severities: Tuple of severity levels to include
            limit: Maximum number of CVEs to return

        Returns:
            DataFrame with CVE details
        """
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'],
                                     ['featureKey', 'name'],
                                     'vulnId',
                                     'severity',
                                     ['fixInfo', 'fix_available'],
                                     ['fixInfo', 'fixed_version'],
                                     ['featureKey', 'version_installed']])

        if 'severity' not in df:
            df['severity'] = False

        # Filter by severity
        df = df[df['severity'].isin(severities)]

        if df.empty:
            return df

        # Clean up column names
        df.rename(columns={
            'evalCtx.hostname': 'Hostname',
            'vulnId': 'CVE',
            'severity': 'Severity',
            'featureKey.name': 'Package Name',
            'featureKey.version_installed': 'Installed Version',
            'fixInfo.fix_available': 'Fix Available',
            'fixInfo.fixed_version': 'Fixed Version(s)'
        }, inplace=True)

        # Sort by severity then CVE
        df['Severity'] = pd.Categorical(df['Severity'], ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['Severity', 'CVE'])

        # Select and reorder columns
        columns_to_keep = ['Severity', 'CVE', 'Hostname', 'Package Name', 'Installed Version']
        if 'Fix Available' in df.columns and 'Fixed Version(s)' in df.columns:
            columns_to_keep.extend(['Fix Available', 'Fixed Version(s)'])

        df = df[columns_to_keep]

        if limit:
            df = df.head(limit)

        return df

    def top_risk_vulns(self, limit=10):
        """Return top vulnerabilities sorted by riskScore descending, with score included.

        Returns:
            DataFrame with CVE, Risk Score, Severity, Hostname, Package, Installed Version, Fix columns.
        """
        if not self.data:
            return pd.DataFrame()
        df = pd.json_normalize(self.data,
                               meta=[['evalCtx', 'hostname'],
                                     ['featureKey', 'name'],
                                     'vulnId',
                                     'severity',
                                     'riskScore',
                                     ['fixInfo', 'fix_available'],
                                     ['fixInfo', 'fixed_version'],
                                     ['featureKey', 'version_installed']])
        if df.empty:
            return df
        df['riskScore'] = pd.to_numeric(df.get('riskScore', pd.Series(dtype=float)), errors='coerce').fillna(0)
        df['severity'] = pd.Categorical(df.get('severity', pd.Series(dtype=str)), ["Critical", "High", "Medium", "Low", "Info"])
        df = df.sort_values(by=['riskScore', 'severity'], ascending=[False, True])
        df = df.drop_duplicates(subset=['vulnId', 'evalCtx.hostname'])
        df.rename(columns={
            'evalCtx.hostname': 'Hostname',
            'vulnId': 'CVE',
            'severity': 'Severity',
            'riskScore': 'Risk Score',
            'featureKey.name': 'Package',
            'featureKey.version_installed': 'Installed Version',
            'fixInfo.fix_available': 'Fix Available',
            'fixInfo.fixed_version': 'Fixed Version'
        }, inplace=True)
        cols = ['CVE', 'Risk Score', 'Severity', 'Hostname', 'Package', 'Installed Version']
        for c in ['Fix Available', 'Fixed Version']:
            if c in df.columns:
                cols.append(c)
        return df[[c for c in cols if c in df.columns]].head(limit)

    def host_patch_priority(self, limit=15):
        """Return list of {hostname, count} dicts sorted by total CVE count descending."""
        if not self.data:
            return []
        df = pd.json_normalize(self.data)
        hostname_col = 'evalCtx.hostname' if 'evalCtx.hostname' in df.columns else 'machineTags.Hostname'
        df = df.groupby(hostname_col).agg(vuln_count=('vulnId', 'count')).reset_index()
        df = df.sort_values('vuln_count', ascending=False).head(limit)
        return [{'hostname': row[hostname_col], 'count': int(row['vuln_count'])} for _, row in df.iterrows()]

    def host_vulns_by_severity_bar(self, severities=["Critical", "High", "Medium", "Low"], width=600, height=500, format='svg'):
        if not self.data:
            return render_host_priority([], [], 'Top Hosts — Patch Priority (Risk Score ≥ 9)',
                                        width, height, fmt=format)
        df = pd.json_normalize(self.data)
        hostname_col = 'evalCtx.hostname' if 'evalCtx.hostname' in df.columns else 'machineTags.Hostname'
        df = df.groupby(hostname_col).agg(vuln_count=('vulnId', 'count')).reset_index()
        df = df.sort_values('vuln_count', ascending=False).head(15)
        labels = df[hostname_col].tolist()
        values = df['vuln_count'].tolist()
        return render_host_priority(labels, values,
                                    title='Top Hosts — Patch Priority (Risk Score ≥ 9)',
                                    width=width, height=height, fmt=format)