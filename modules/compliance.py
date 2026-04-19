import pandas as pd

import plotly.graph_objects as go
from logzero import logger
from modules.chart_utils import render_bubbles


def process_compliance_violations(violations):
    output_string = ''
    for violation in violations:
        formatted_string = f"Region:{violation['region']}" + '\n' + f"Resource: {violation['resource']}" + '\n' + f"Reasons: {violation['reasons']}" + '\n\n'
        output_string += formatted_string
    return output_string
class Compliance:

    def __init__(self, data: dict):
        self.cloud_provider = data['cloud_provider']
        self.report_type = data['report_type']
        self.reports = data['reports']
        self.all_recommendations = self.get_all_recommendations()
        if self.cloud_provider == 'AWS':
            self.account_id_string = 'ACCOUNT_ID'
            self.account_id_rename_string = 'Account ID'
        if self.cloud_provider == 'AZURE':
            self.account_id_string = 'SUBSCRIPTION_ID'
            self.account_id_rename_string = 'Subscription ID'
        if self.cloud_provider == 'GCP':
            self.account_id_string = 'PROJECT_ID'
            self.account_id_rename_string = 'Project ID'

    def get_all_recommendations(self):
        results = []
        for entry in self.reports:
            report_type = entry['reportType']
            for recommendation in entry['recommendations']:
                results.append({**{'reportType': report_type}, **recommendation})
        return results

    def get_total_accounts_evaluated(self):
        df = pd.DataFrame(self.all_recommendations)
        unique_accounts = df[self.account_id_string].nunique()
        return unique_accounts

    def get_unique_critical_finding_count(self):
        """
        Count unique critical compliance findings across all accounts.
        If the same control fails in multiple accounts, it's only counted once.

        Returns:
            Integer count of unique critical findings
        """
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df = df[df['SEVERITY'] == 1]  # Critical severity

        # Count unique TITLE values (unique compliance controls)
        unique_critical_count = df['TITLE'].nunique()
        return unique_critical_count

    def get_unique_finding_count(self, severities=["Critical"]):
        """
        Count unique compliance findings across all accounts for specified severities.
        If the same control fails in multiple accounts, it's only counted once.

        Args:
            severities: List of severity strings to include

        Returns:
            Integer count of unique findings
        """
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        # Count unique TITLE values (unique compliance controls)
        unique_finding_count = df['TITLE'].nunique()
        return unique_finding_count

    def get_compliance_details(self, severities=["Critical"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())

        df = df.sort_values(by=['SEVERITY', 'RESOURCE_COUNT'], ascending=[True, False])

        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        df = df.reset_index()

        df['Resources'] = df['RESOURCE_COUNT'].astype('string') + " / " + df['ASSESSED_RESOURCE_COUNT'].astype('string')

        df = df[[self.account_id_string, 'CATEGORY', 'TITLE', 'SEVERITY', 'Resources']]
        df.rename(columns={self.account_id_string: self.account_id_rename_string, 'CATEGORY': 'Category',
                           'TITLE': 'Title', 'SEVERITY': 'Severity'},
                  inplace=True)

        return df

    def critical_compliance_details(self):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df = df[df['SEVERITY'] == 1]
        df = df[[self.account_id_string, 'CATEGORY', 'TITLE', 'VIOLATIONS']]
        df.rename(columns={self.account_id_string: self.account_id_rename_string,
                           'CATEGORY': 'Category',
                           'TITLE': 'Control',
                           'VIOLATIONS': 'Violations'}, inplace=True)
        df['Violations'] = df['Violations'].apply(process_compliance_violations)

        return df

    def get_compliance_summary(self, severities=["Critical"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]

        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())

        df = df.sort_values(by=['SEVERITY', 'RESOURCE_COUNT'], ascending=[True, False])

        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        df = df.groupby([self.account_id_string, 'SEVERITY']).agg(count=('SEVERITY', 'count'),
                                                        resources=('RESOURCE_COUNT', 'sum'),
                                                        assessed=('ASSESSED_RESOURCE_COUNT',
                                                                  'sum')).reset_index()  # .size().reset_index(name='count')
        df['sev_merged'] = df['SEVERITY'].astype('string') + ": " + df['count'].astype('string')

        df = df.groupby(self.account_id_string).agg(
            {'sev_merged': f"\n".join, 'resources': 'sum', 'assessed': 'sum'}).reset_index()
        df.rename(
            columns={self.account_id_string: self.account_id_rename_string, 'sev_merged': 'Severity Count',
                     'resources': 'Non-compliant Resources','assessed': 'Total Assessed Resources'},
            inplace=True)


        return df

    def get_summary_by_account(self, severities=["Critical"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())
        # sort to determine account order, while we still have the severity & resource count data
        df = df.sort_values(by=['SEVERITY', 'RESOURCE_COUNT'], ascending=[True, False])
        account_order = df[self.account_id_string].unique()


        # group
        df = df.groupby([self.account_id_string, 'SEVERITY']).agg(failed_control_count=('SEVERITY', 'count'),
                                                        failed_resources=('RESOURCE_COUNT', 'sum')).reset_index()

        # sort by accounts with most criticals, followed by most highs
        df[self.account_id_string] = pd.Categorical(df[self.account_id_string], account_order)
        df.sort_values(by=[self.account_id_string, 'SEVERITY'], ascending=True)

        # convert int and filter severities
        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        # rename
        df.rename(
            columns={self.account_id_string: self.account_id_rename_string, 'SEVERITY': 'Severity', 'failed_resources': 'Non-compliant Resources',
                     'failed_control_count': 'Failed controls'}, inplace=True)

        # pivot and preseve severity order (pivot breaks this)
        severity_order = df['Severity'].unique()
        df = pd.pivot_table(df, values='Non-compliant Resources', index=self.account_id_rename_string, columns='Severity', sort=False)
        df = df.reindex(severity_order, axis=1)

        return df

    def get_summary_by_service(self, severities=["Critical"]):
        df = pd.DataFrame(self.all_recommendations)
        df = df[df['STATUS'].isin(["NonCompliant"])]
        df = df.replace({'SEVERITY': {1: "Critical", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}})
        df = df[df['SEVERITY'].isin(severities)]

        df['RESOURCE_COUNT'] = (df['VIOLATIONS'].str.len())

        df = df.reset_index()

        df = df[[self.account_id_string, 'CATEGORY', 'SEVERITY', 'RESOURCE_COUNT']]

        # group by acct id, category
        df = df.groupby([self.account_id_string, 'CATEGORY']).agg(count=('RESOURCE_COUNT', 'sum')).reset_index()

        # determine category order
        df_category_order = df.groupby(['CATEGORY']).agg(count=('count', 'sum')).reset_index()
        df_category_order.sort_values('count', ascending=False, inplace=True)
        df_category_order = df_category_order['CATEGORY'].unique()
        df = df.astype({'CATEGORY': pd.CategoricalDtype(df_category_order, ordered=True)})

        # create pivot table
        df = pd.pivot_table(df, values='count', index=self.account_id_string, columns='CATEGORY', sort=False)
        return df

    def get_summary_by_account_bar_graph(self, width=600, height=450, format='svg'):
        df = pd.DataFrame(self.all_recommendations)
        df = df[(df['STATUS'] == 'NonCompliant') & (df['SEVERITY'] == 1)]
        df['RESOURCE_COUNT'] = df['VIOLATIONS'].str.len()
        df = df.groupby(self.account_id_string)['RESOURCE_COUNT'].sum().reset_index()
        labels = df[self.account_id_string].tolist()
        values = df['RESOURCE_COUNT'].tolist()
        return render_bubbles(labels, values,
                              title=f'Critical Non-Compliance by {self.account_id_rename_string}',
                              width=width, height=height, fmt=format, unit='Failed Resources')

    def get_summary_by_service_bar_graph(self, width=600, height=500, format='svg'):
        df = pd.DataFrame(self.all_recommendations)
        df = df[(df['STATUS'] == 'NonCompliant') & (df['SEVERITY'] == 1)]
        df['RESOURCE_COUNT'] = df['VIOLATIONS'].str.len()
        df = df.groupby('TITLE')['RESOURCE_COUNT'].sum().reset_index()
        df = df.sort_values('RESOURCE_COUNT', ascending=False).head(10)
        labels = df['TITLE'].tolist()
        values = df['RESOURCE_COUNT'].tolist()
        return render_bubbles(labels, values,
                              title='Top 10 Critical Non-Compliant Controls',
                              width=width, height=height, fmt=format, unit='Failed Resources')