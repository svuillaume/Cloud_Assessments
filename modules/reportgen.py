import os
import sys
import traceback
import jinja2
import base64
from datetime import datetime
from logzero import logger
from modules.lacework_interface import LaceworkInterface
from modules.compliance import Compliance
from modules.alerts import Alerts
from modules.host_vulnerabilities import HostVulnerabilities
from modules.container_vulnerabilities import ContainerVulnerabilities
from modules.secrets import Secrets
from modules.utils import LaceworkTime


class ReportGen:

    report_short_name = 'Base'
    report_name = "Base Report Class"
    report_description = "This is the base report class, it should be inherited from, not imported directly."

    def __init__(self, basedir, use_cache=False, api_key_file=None, graph_scale=1):
        self.basedir = basedir
        self.use_cache = use_cache
        self.graph_scale = graph_scale
        self.lacework_interface = LaceworkInterface(use_cache=use_cache, api_key_file=api_key_file)

    def file_to_image_tag(self, img_file: str, file_format: str, align="left") -> str:
        img_bytes = self.load_binary_file(img_file)
        return self.bytes_to_image_tag(img_bytes,file_format, align=align)

    def bytes_to_image_tag(self, img_bytes: bytes, file_format: str, align="left") -> str:
        b64content = base64.b64encode(img_bytes).decode('utf-8')
        return f"<img src='data:image/{file_format};charset=utf-8;base64,{b64content}' align='{align}'/>"

    def file_to_css_background(self, img_file: str, file_format: str) -> str:
        img_bytes = self.load_binary_file(img_file)
        b64content = base64.b64encode(img_bytes).decode('utf-8')
        return f"background-image: url(data:image/{file_format};base64,{b64content}>);"

    def file_to_css_font(self, font_file: str, file_format: str) -> str:
        font_bytes = self.load_binary_file(font_file)
        b64content = base64.b64encode(font_bytes).decode('utf-8')
        return f"src: url('data:font/{file_format};charset=utf-8;base64,{b64content}') format('{file_format}');"

    def generate_qr_code(self, url: str, box_size: int = 4, border: int = 2) -> str:
        import qrcode, io
        qr = qrcode.QRCode(version=1, box_size=box_size, border=border)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return self.bytes_to_image_tag(buf.getvalue(), 'png')

    def load_binary_file(self, path: str) -> bytes:
        full_path = os.path.join(self.basedir, path)
        with open(full_path, "rb") as in_file:
            file_bytes = in_file.read()
        return file_bytes

    def get_jinja2_template(self, file_name: str) -> jinja2.Template:
        template_loader = jinja2.FileSystemLoader(searchpath=os.path.join(self.basedir, "templates/"))
        template_env = jinja2.Environment(loader=template_loader, autoescape=True, trim_blocks=True, lstrip_blocks=True)
        template_file = file_name
        try:
            return template_env.get_template(template_file)
        except Exception as e:
            logger.error(f'Could not load html template {str(file_name)}, EXITING: {str(e)}')
            sys.exit()

    def get_current_date(self) -> str:
        return datetime.now().strftime("%A %B %d, %Y")

    def gather_host_vulnerability_data(self, begin_time: str, end_time: str, host_limit: int = 25):
        print('Gathering vulnerability data for hosts.')
        try:
            self.lacework_interface.use_cache = self.use_cache
            host_vulnerabilities: HostVulnerabilities = self.lacework_interface.get_host_vulns(begin_time, end_time)
        except Exception as e:
            logger.error(
                f'Failed to retrieve host vulnerability data from Lacework, omitting it from the report.')
            logger.error(f"Exception: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        if not host_vulnerabilities.data:
            logger.error("No host vulnerability data was returned by Lacework, omitting it from the report.")
            return False
        total_evaluated = host_vulnerabilities.total_evaluated()
        summary_by_host = host_vulnerabilities.summary_by_host(limit=host_limit)
        summary_by_host.style.set_table_attributes('class="host_vulns_summary_by_host"')
        summary = host_vulnerabilities.summary()
        summary.style.set_table_attributes('class="host_vulns_summary"')
        critical_vulnerability_count = summary.loc[summary['Severity'] == 'Critical', 'Hosts Affected'].values[0]
        summary_bar_graphic = host_vulnerabilities.host_vulns_by_severity_bar(width=1200 * self.graph_scale, height=350 * self.graph_scale)
        summary_bar_graphic_encoded = self.bytes_to_image_tag(summary_bar_graphic, "svg+xml", align='middle')
        fixable_vulns = host_vulnerabilities.fixable_vulns(severities=["Critical"])
        all_cves_detail = host_vulnerabilities.all_cves_detail(severities=("High", "Medium", "Low"), limit=100)
        top_risk_vulns = host_vulnerabilities.top_risk_vulns(limit=10)
        return {
            'hosts_scanned_count': total_evaluated,
            'host_vulns_summary': summary,
            'host_vulns_summary_bar_graphic': summary_bar_graphic_encoded,
            'host_vulns_summary_by_host': summary_by_host,
            'critical_vuln_count': critical_vulnerability_count,
            'host_vulns_summary_by_host_limit': host_limit,
            'fixable_vulns': fixable_vulns,
            'all_cves_detail': all_cves_detail,
            'top_risk_vulns': top_risk_vulns,
            'host_patch_priority': host_vulnerabilities.host_patch_priority(limit=15)
        }

    def gather_container_vulnerability_data(self, begin_time: str, end_time: str, container_limit: int = 25):
        print('Gathering vulnerability data for containers.')
        try:
            self.lacework_interface.use_cache = self.use_cache
            container_vulnerabilities: ContainerVulnerabilities = self.lacework_interface.get_container_vulns(begin_time, end_time)
        except Exception as e:
            logger.error(
                f'Failed to retrieve container vulnerability data from Lacework, omitting it from the report.')
            logger.error(f"Exception: {str(e)}")
            logger.error(traceback.format_exc())
            return False

        if not container_vulnerabilities.data:
            logger.error("No container vulnerability data was returned by Lacework, omitting it from the report.")
            return False
        total_evaluated = container_vulnerabilities.total_evaluated()
        summary_by_image = container_vulnerabilities.summary_by_image(limit=container_limit)
        summary_by_image.style.set_table_attributes('class="container_vulns_summary_by_image"')
        summary = container_vulnerabilities.summary()
        summary.style.set_table_attributes('class="container_vulns_summary"')
        critical_vulnerability_count = summary.loc[summary['Severity'] == 'Critical', 'Images Affected'].values[0]
        summary_by_package_bar = container_vulnerabilities.top_packages_bar(width=1200 * self.graph_scale, height=350 * self.graph_scale)
        summary_by_package_bar_encoded = self.bytes_to_image_tag(summary_by_package_bar, 'svg+xml', align='middle')
        fixable_vulns = container_vulnerabilities.fixable_vulns(severities=['Critical'])
        top_risk_vulns = container_vulnerabilities.top_risk_vulns(limit=10)
        return {
            'containers_scanned_count': total_evaluated,
            'container_vulns_summary': summary,
            'container_vulns_summary_by_package_bar_graphic': summary_by_package_bar_encoded,
            'container_vulns_summary_by_image': summary_by_image,
            'critical_vuln_count': critical_vulnerability_count,
            'container_vulns_summary_by_image_limit': container_limit,
            'fixable_vulns': fixable_vulns,
            'top_risk_vulns': top_risk_vulns
        }

    def gather_compliance_data(self, cloud_provider='AWS', report_type='CIS'):
        print(f'Getting {report_type} compliance reports for {cloud_provider}')
        try:
            self.lacework_interface.use_cache = self.use_cache
            compliance_reports: Compliance = self.lacework_interface.get_compliance_reports(cloud_provider=cloud_provider, report_type=report_type)
        except Exception as e:
            logger.error(f'Failed to retrieve {report_type} report(s) for {cloud_provider}, omitting them from the report.')
            logger.error(f"Exception: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        if not compliance_reports.reports:
            logger.error(f'Reports of type {report_type} from {cloud_provider} came back empty. Omitting them from the report.')
            return False
        # set table classes
        details = compliance_reports.get_compliance_details()

        details.style.set_table_attributes('class="compliance_detail"')
        print(details)
        summary = compliance_reports.get_compliance_summary()
        summary.style.set_table_attributes('class="compliance_summary"')
        print(summary)
        # get graphics
        findings_by_account_bar_graph = compliance_reports.get_summary_by_account_bar_graph(width=1200 * self.graph_scale,  height=350 * self.graph_scale)
        findings_by_account_bar_graph_encoded = self.bytes_to_image_tag(findings_by_account_bar_graph, 'svg+xml', align='middle')

        findings_summary_by_service_bar_graph = compliance_reports.get_summary_by_service_bar_graph(width=1200 * self.graph_scale, height=350 * self.graph_scale)
        findings_summary_by_service_bar_graph_encoded = self.bytes_to_image_tag(findings_summary_by_service_bar_graph, 'svg+xml', align='middle')
        critical_details = compliance_reports.critical_compliance_details()
        summary_by_account = compliance_reports.get_summary_by_account()

        # Count unique compliance findings (not resources) across all accounts
        # If the same control fails in multiple accounts, it's only counted once
        summary_count = compliance_reports.get_unique_finding_count(severities=["Critical"])
        critical_finding_count = compliance_reports.get_unique_critical_finding_count()

        return {
            'cloud_accounts_count': compliance_reports.get_total_accounts_evaluated(),
            'compliance_summary': summary,
            'compliance_findings_by_service_bar_graphic': findings_summary_by_service_bar_graph_encoded,
            'compliance_findings_by_account_bar_graphic': findings_by_account_bar_graph_encoded,
            'compliance_detail': details,
            'summary_count': summary_count,
            'critical_finding_count': critical_finding_count,
            'critical_details': critical_details
        }

    def gather_secrets(self, begin_time: str, end_time: str):
        print('Getting secrets...')
        try:
            self.lacework_interface.use_cache = self.use_cache
            secrets: Secrets = self.lacework_interface.get_secrets(begin_time, end_time)
        except Exception as e:
            logger.error(
                f'Failed to retrieve secrets data from Lacework, omitting it from the report.')
            logger.error(f"Exception: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        total = secrets.count_secrets()
        risky = secrets.risky_secrets_count()
        legacy = secrets.legacy_rsa_count()
        print(f'Found {total} total secrets ({risky} in risky locations, {legacy} legacy ssh-rsa)')
        return {
            "secrets_raw": secrets.processed_secrets(),
            "secrets_html": secrets.styled_secrets_html(),
            "secrets_count": total,
            "risky_secrets_count": risky,
            "legacy_rsa_count": legacy,
        }

    def gather_alert_data(self, begin_time: str, end_time: str):
        print('Getting alert data...')
        try:
            self.lacework_interface.use_cache = self.use_cache
            alerts: Alerts = self.lacework_interface.get_alerts(begin_time, end_time)
        except Exception as e:
            logger.error(
                f'Failed to retrieve alert data from Lacework, omitting it from the report.')
            logger.error(f"Exception: {str(e)}")
            logger.error(traceback.format_exc())
            return False
        print(f'Found {alerts.count_alerts()} total alerts.')
        if alerts.count_alerts() > 0:
            processed_alerts = alerts.processed_alerts(limit=25)
            high_critical_finding_count = len(processed_alerts[processed_alerts['Severity'].isin(['Critical'])])
            print(f'Found {high_critical_finding_count} high and critical alerts.')

            return {
                'alerts_raw': processed_alerts,
                'high_critical_finding_count': high_critical_finding_count
            }
        else:
            return None

    def gather_identity_entitlement_data(self, begin_time: str, end_time: str, threshold: int = 70):
        """
        Gather CIEM data for AWS, Azure, GCP identities

        Args:
            begin_time: ISO timestamp
            end_time: ISO timestamp
            threshold: Unused entitlement threshold (default 70)

        Returns:
            Dictionary with CIEM data for all providers or False on error
        """
        print('Gathering identity and entitlement data (CIEM)...')

        # Get ALL identities in one query
        try:
            self.lacework_interface.use_cache = self.use_cache
            all_identity_entitlements = self.lacework_interface.get_identity_entitlements(
                begin_time,
                end_time
            )
        except Exception as e:
            logger.error(f'Failed to retrieve CIEM data: {str(e)}')
            logger.error(traceback.format_exc())
            return False

        if not all_identity_entitlements.data:
            logger.error("No CIEM data returned. CIEM may not be enabled for this account.")
            logger.info("Skipping CIEM section in report.")
            return False

        print(f'Total identities retrieved: {all_identity_entitlements.count_identities()}')

        # Now filter by provider and process each separately
        ciem_data = {}
        from modules.identity_entitlements import IdentityEntitlements

        # Define per-provider thresholds
        provider_thresholds = {
            'AWS': threshold,
            'AZURE': threshold,
            'GCP': threshold
        }

        for provider in ['AWS', 'AZURE', 'GCP']:
            # Filter identities by provider type
            provider_identities = [identity for identity in all_identity_entitlements.data
                                   if identity.get('PROVIDER_TYPE') == provider]

            if not provider_identities:
                logger.warning(f"No CIEM data returned for {provider}")
                ciem_data[provider] = None
                continue

            # Create a new IdentityEntitlements object for this provider
            identity_entitlements = IdentityEntitlements({'data': provider_identities})

            # Use provider-specific threshold
            provider_threshold = provider_thresholds[provider]

            # Get critical identities (root + high privileges)
            critical_identities = identity_entitlements.get_critical_identities(provider_threshold)
            high_privilege_identities = identity_entitlements.get_high_privilege_identities(provider_threshold)
            root_identities = identity_entitlements.get_root_identities()

            print(f'{provider}: Total identities analyzed: {identity_entitlements.count_identities()}')
            print(f'{provider}: High privilege identities (≥{provider_threshold} unused entitlements): {len(high_privilege_identities)}')
            print(f'{provider}: Root/admin identities: {len(root_identities)}')
            print(f'{provider}: Critical (root + ≥{provider_threshold} unused): {len(critical_identities)}')

            # Get all identities for display (top 25)
            all_identities = identity_entitlements.get_all_identities(limit=25)

            # For Azure, also get count of identities with ≥80 for executive summary
            high_risk_count_80 = 0
            if provider == 'AZURE':
                high_risk_80 = identity_entitlements.get_high_privilege_identities(80)
                high_risk_count_80 = len(high_risk_80)
                print(f'{provider}: High risk identities (≥80 unused entitlements): {high_risk_count_80}')

            # Process data for this provider
            ciem_data[provider] = {
                'high_privilege_count': len(high_privilege_identities),
                'root_count': len(root_identities),
                'critical_count': len(critical_identities),
                'critical_identities': critical_identities,
                'high_privilege_identities': high_privilege_identities,
                'root_identities': root_identities,
                'all_identities': all_identities,
                'threshold': provider_threshold,
                'total_identities': identity_entitlements.count_identities()
            }

            # Add Azure-specific high risk count for executive summary
            if provider == 'AZURE':
                ciem_data[provider]['high_risk_count_80'] = high_risk_count_80

        # Check if we got any data from at least one provider
        providers_with_data = [k for k, v in ciem_data.items() if v is not None]

        if not providers_with_data:
            logger.error("No CIEM data retrieved for any provider. CIEM may not be enabled for this account.")
            logger.info("Skipping CIEM section in report.")
            return False

        if len(providers_with_data) < 3:
            logger.info(f"CIEM data available for: {', '.join(providers_with_data)}")
            missing_providers = [k for k, v in ciem_data.items() if v is None]
            logger.warning(f"No CIEM data for: {', '.join(missing_providers)} (may not be configured)")

        return ciem_data

    def gather_data(self,
                 vulns_start_time: LaceworkTime,
                 vulns_end_time: LaceworkTime,
                 alerts_start_time: LaceworkTime,
                 alerts_end_time: LaceworkTime):
        pass

    def render(self, customer, author, custom_logo=None, pagesize="a3", pdf=False):
        pass

    def generate(self,
                 customer: str,
                 author: str,
                 vulns_start_time: LaceworkTime,
                 vulns_end_time: LaceworkTime,
                 alerts_start_time: LaceworkTime,
                 alerts_end_time: LaceworkTime):
        self.gather_data(vulns_start_time,
                         vulns_end_time,
                         alerts_start_time,
                         alerts_end_time)
        return self.render(customer, author, custom_logo=None, pdf=False)



