import json

from laceworksdk import LaceworkClient
from logzero import logger
from modules.host_vulnerabilities import HostVulnerabilities
from modules.container_vulnerabilities import ContainerVulnerabilities
from modules.alerts import Alerts
from modules.compliance import Compliance
from modules.secrets import Secrets
from modules.identity_entitlements import IdentityEntitlements
from modules.utils import cache_results


class LaceworkInterface:

    def __init__(self, api_key_file=None, use_cache=False):
        if api_key_file:
            if 'subAccount' in api_key_file:
                self.lacework = LaceworkClient(account=api_key_file['account'],
                                               subaccount=api_key_file['subAccount'],
                                               api_key=api_key_file['keyId'],
                                               api_secret=api_key_file['secret']
                                               )
            else:
                self.lacework = LaceworkClient(account=api_key_file['account'],
                                               api_key=api_key_file['keyId'],
                                               api_secret=api_key_file['secret']
                                               )
        else:
            self.lacework = LaceworkClient()
        self.use_cache = use_cache
        self.compliance_provider_lookup = {'AWS': 'AwsCfg',
                                           'GCP': 'GcpCfg',
                                           'AZURE': 'AzureCfg'}
        self.compliance_report_lookup = {
            'AwsCfg': {
                'CIS':         'AWS_CIS_14',
                'PCI':         'AWS_PCI_DSS_3.2.1',
                'NIST_CSF':    'AWS_NIST_CSF',
                'NIST_800_53': 'AWS_NIST_800-53_rev5',
                'SOC2':        'AWS_SOC_2',
                'HIPAA':       'AWS_HIPAA',
                'ISO_27001':   'AWS_ISO_27001:2013',
                'CSA_CCM':     'AWS_CSA_CCM_4_0_5',
            },
            'AzureCfg': {
                'CIS':         'AZURE_CIS_1_5',
                'PCI':         'AZURE_PCI_DSS_3_2_1_CIS_1_5',
                'NIST_CSF':    'AZURE_NIST_CSF',
                'NIST_800_53': 'AZURE_NIST_800-53_rev5',
                'HIPAA':       'AZURE_HIPAA',
                'ISO_27001':   'AZURE_ISO_27001:2013',
                'CSA_CCM':     'AZURE_CSA_CCM_4_0_5',
            },
            'GcpCfg': {
                'CIS':         'GCP_CIS13',
                'PCI':         'GCP_PCI_Rev2',
                'NIST_CSF':    'GCP_NIST_CSF',
                'NIST_800_53': 'GCP_NIST_800-53_rev5',
                'HIPAA':       'GCP_HIPAA',
                'ISO_27001':   'GCP_ISO_27001:2013',
                'CSA_CCM':     'GCP_CSA_CCM_4_0_5',
            },
        }

    def write_json_file(self, obj, name):
        with open(name, 'w') as f:
            json.dump(obj, f)

    @cache_results
    def get_cfg_account_ids(self):
        try:
            accounts = self.lacework.cloud_accounts.get()['data']
        except Exception as e:
            logger.error(f"Failed to retrieve list of cloud accounts from Lacework API:{str(e)}")
            raise e
        account_details = []
        config_accounts = [account for account in accounts if ("Cfg" in account['type'] and account['enabled'] == 1 and account['state']['ok'] is True)]
        for config_account in config_accounts:
            logger.debug(f"Found Account: {json.dumps(config_account['data'])}")
            if config_account['type'] == 'GcpCfg':
                #project_data = self.lacework.configs.gcp_projects.get()
                account_details.append({'name': config_account['name'],
                                        'type': config_account['type'],
                                        'primary_query_id': None,
                                        'secondary_query_id': config_account['data']['id'],
                                        })
            elif config_account['type'] == 'AzureCfg':
                tenant_data = self.lacework.configs.azure_subscriptions.get(tenantId=config_account['data']['tenantId'])['data']
                for tenant in tenant_data:
                    for subscription in tenant['subscriptions']:
                        #logger.info(f"Adding tenant:{config_account['data']['tenantId']} Subscription:{str(subscription).split(' ')[0]}")
                        account_details.append({'name': config_account['name'],
                                                'type': config_account['type'],
                                                'primary_query_id': config_account['data']['tenantId'],
                                                'secondary_query_id': str(subscription).split(' ')[0],
                                                })
            elif config_account['type'] == 'AwsCfg':
                arn_elements = config_account['data']['crossAccountCredentials']['roleArn'].split(':')
                account_details.append({'name': config_account['name'],
                                        'type': config_account['type'],
                                        'primary_query_id': arn_elements[4],
                                        'secondary_query_id': None,
                                        })
        return account_details

    def get_alert_entity_map(self, alert_id):
        """Fetch entityMap for a single alert (IP, DNS, GeoIP, VirusTotal).
        Uses get_details(scope='Details') which returns the enriched entity map.
        Not cached — called for the top 10 critical alerts only."""
        try:
            aid = int(alert_id)  # pandas int64 → plain int
            # get_details returns a single dict under 'data', not a list
            resp = self.lacework.alerts.get_details(alert_id=aid, scope='Details')
            data = resp.get('data', {})
            if isinstance(data, list):
                data = data[0] if data else {}
            entity_map = data.get('entityMap', {})
            if entity_map:
                return entity_map
            # Fallback: basic get() in case SDK version differs
            resp2 = self.lacework.alerts.get(alert_id=aid)
            data2 = resp2.get('data', [{}])
            if isinstance(data2, list):
                data2 = data2[0] if data2 else {}
            return data2.get('entityMap', {})
        except Exception as e:
            logger.warning(f"Could not fetch entity data for alert {alert_id}: {e}")
            return {}

    @cache_results
    def get_alerts(self, start_time, end_time, severities=('Critical', 'High')):
        logger.debug(f'Getting alerts from {start_time} to {end_time}:')
        alerts_list = []
        for severity in severities:
            filters = {
                "timeFilter": {
                    "startTime": start_time,
                    "endTime": end_time
                },
                "filters":
                    [
                        {
                            "field": "severity",
                            "expression": "eq",
                            "value": severity
                        }
                    ]
            }

            try:
                alerts = self.lacework.alerts.search(json=filters)
            except Exception as e:
                logger.error(f"Failed to retrieve list of alerts from Lacework API:{str(e)}")
                raise e
            i = 1
            for page in alerts:
                logger.info('Saving page ' + str(i))
                i = i + 1
                alerts_list.extend(page['data'])
            if i > 100:
                logger.warning(
                    "Lacework API returned maximum pages of host vuln results (100 pages). Processed dataset is likely incomplete.")
        logger.info(f'{len(alerts_list)} alerts returned.')
        alerts = Alerts(alerts_list)
        return alerts

    @cache_results
    def get_secrets(self, start_time, end_time):
        logger.debug(f'Getting secrets from {start_time} to {end_time}:')
        lql_query = "{source { LW_HE_SECRETS_SSH_PRIVATE_KEYS } return {HOSTNAME, FILE_PATH, SSH_KEY_TYPE} }"
        lql_query_args = {"StartTimeRange": start_time,
                          "EndTimeRange": end_time}

        try:
            secrets = self.lacework.queries.execute(query_text=lql_query, arguments=lql_query_args)
        except Exception as e:
            logger.error(f"Failed to retrieve list of secrets from Lacework API:{str(e)}")
            raise e
        return Secrets(secrets)

    @cache_results
    def get_identity_entitlements(self, start_time, end_time):
        """
        Query LW_CE_IDENTITIES datasource for identity and entitlement data
        Returns ALL identities from all cloud providers in one query

        Args:
            start_time: ISO format timestamp
            end_time: ISO format timestamp

        Returns:
            IdentityEntitlements object
        """
        logger.debug(f'Getting identity entitlements from {start_time} to {end_time}:')

        lql_query = """
        {
          source {
            LW_CE_IDENTITIES
          }
          return distinct {
            RECORD_CREATED_TIME,
            PRINCIPAL_ID,
            PROVIDER_TYPE,
            DOMAIN_ID,
            NAME,
            LAST_USED_TIME,
            CREATED_TIME,
            METRICS,
            TAGS,
            ACCESS_KEYS,
            ACCESS_KEYS_LIST,
            ENTITLEMENT_COUNTS
          }
        }
        """

        lql_query_args = {
            "StartTimeRange": start_time,
            "EndTimeRange": end_time
        }

        try:
            logger.debug(f"Executing LQL query for all identities...")
            identity_data = self.lacework.queries.execute(
                query_text=lql_query,
                arguments=lql_query_args
            )
        except Exception as e:
            logger.error(f"Failed to retrieve identity entitlements: {str(e)}")
            logger.debug(f"Query was: {lql_query}")
            logger.debug(f"Arguments were: {lql_query_args}")
            raise e

        identity_count = len(identity_data.get("data", []))
        logger.info(f'{identity_count} total identities returned.')

        if identity_count == 0:
            logger.warning(f"No identity data found. CIEM may not be enabled for this account.")

        return IdentityEntitlements(identity_data)

    @cache_results
    def get_host_vulns(self, start_time, end_time):
        filters = {
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "filters": [
                {
                    "field": "severity",
                    "expression": "eq",
                    "value": "Critical"
                }
            ]
        }
        logger.debug(f'Getting Host Vulns with following filters:{filters}')

        try:
            host_vulns = self.lacework.vulnerabilities.hosts.search(json=filters)
        except Exception as e:
            logger.error(f"Failed to retrieve list of host vulnerabilities from Lacework API:{str(e)}")
            raise e

        results = []
        i = 1
        for page in host_vulns:
            logger.info('Saving page ' + str(i) + f' with {len(page.get("data", []))} records')
            i += 1
            results.extend(page['data'])
        if i > 100:
            logger.warning(
                "Lacework API returned maximum pages of host vuln results (100 pages). Processed dataset is likely incomplete.")

        logger.info(f'Total host vulnerability records retrieved: {len(results)}')
        return HostVulnerabilities(results)

    @cache_results
    def get_container_vulns(self, start_time, end_time):
        filters = {
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "filters": [
                {
                    "field": "severity",
                    "expression": "eq",
                    "value": "Critical"
                }
            ]
        }
        logger.debug(f'Getting Container Vulnerabilities with following filters:{filters}')
        try:
            container_vulns = self.lacework.vulnerabilities.containers.search(json=filters)
        except Exception as e:
            logger.error(f"Failed to retrieve list of container vulnerabilities from Lacework API:{str(e)}")
            raise e

        results = []
        i = 1
        for page in container_vulns:
            logger.info('Saving page ' + str(i))
            i += 1
            results.extend(page['data'])
        if i > 100:
            logger.warning(
                "Lacework API returned maximum pages of container vuln results (100 pages). Processed dataset is likely incomplete.")

        return ContainerVulnerabilities(results)

    @cache_results
    def get_compliance_reports(self, cloud_provider='AWS', report_type='CIS'):
        '''Retrieve all reports of specified type for specified cloud provider.
            Valid Cloud Providers are: AWS, GCP, AZURE
            Valid Report Types are: CIS, PCI
            '''
        compliance_reports = []
        compliance_provider = self.compliance_provider_lookup[str(cloud_provider).upper()]
        compliance_accounts = self.get_cfg_account_ids()
        for compliance_account in compliance_accounts:
            if compliance_account['type'] == compliance_provider:
                report_query_string = self.compliance_report_lookup[compliance_account['type']][report_type]
                logger.debug(f"Getting {report_query_string} report for {compliance_account}")
                try:
                    report = self.lacework.reports.get(primary_query_id=compliance_account['primary_query_id'],
                                                       secondary_query_id=compliance_account['secondary_query_id'],
                                                       format="json",
                                                       latest=True,
                                                       report_type=report_query_string)
                except Exception as e:
                    logger.error(f"Failed to retrieve {report_type} report for {cloud_provider} from Lacework API:{str(e)}")
                    raise e

                logger.info(f"{cloud_provider}:{report_type}:{compliance_account['primary_query_id']}:{compliance_account['secondary_query_id']}:"
                            f"Compliance Results:{len(report['data'][0]['recommendations']) if report['data'] else 0}")
                if report['data']:
                    compliance_reports.append(report['data'][0])
        results = Compliance({'cloud_provider': cloud_provider,
                              'report_type': report_type,
                              'reports': compliance_reports})
        return results






