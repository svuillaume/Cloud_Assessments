from modules.reportgen import ReportGen
from modules.utils import LaceworkTime
import os

class ReportGenCSADetailed(ReportGen):

    report_short_name = 'CSA_Detailed'
    report_name = 'Rapid Cloud Assessment Report – FortiCNAPP'
    report_description = "Executive-ready Rapid Cloud Assessment covering FortiCNAPP compliance findings, vulnerabilities (Risk Score ≥ 9), identity & entitlement risk, and critical alerts with leadership decision support and a 30–60–90 day action plan."
    default_recommendations = ""

    def __init__(self, basedir, use_cache=False, api_key_file=None, graph_scale=1):
        super().__init__(basedir, use_cache=use_cache, api_key_file=api_key_file, graph_scale=graph_scale)
        self.recommendations = self.default_recommendations
        self.template = self.get_jinja2_template('csa_detailed_report.jinja2')
        self.company_logo_html = self.file_to_image_tag('assets/Fortinet_logo.png', 'png')
        self.rca_logo_html = self.file_to_image_tag('assets/rca_logo.png', 'png')
        self.polygraph_graphic_html = self.file_to_image_tag('assets/FortiCNAPP-Unified-Approach.png', 'png')
        self.sec_outcomes_html = self.file_to_image_tag('assets/sec_outcomes.png', 'png')
        self.cloud_status_quo_html = self.file_to_image_tag('assets/CloudStatusQuo.png', 'png')
        self.fortinet_sec_fabric_html = self.file_to_image_tag('assets/FortinetSecFabric.png', 'png')
        self.forticnapp_platform_html = self.file_to_image_tag('assets/FortiCNAPP.png', 'png')
        self.state_of_cloud_html = self.file_to_image_tag('assets/StateofCloud_SecReport.png', 'png')
        self.fortinet_resources_qr_html = self.generate_qr_code('https://www.fortinet.com/resources/reports/cloud-security')

    def gather_data(self,
                    vulns_start_time: LaceworkTime,
                    vulns_end_time: LaceworkTime,
                    alerts_start_time: LaceworkTime,
                    alerts_end_time: LaceworkTime,
                    ciem_threshold: int = 70):

        self.aws_compliance_data=self.gather_compliance_data(cloud_provider='AWS')
        self.azure_compliance_data=self.gather_compliance_data(cloud_provider='AZURE')
        self.gcp_compliance_data=self.gather_compliance_data(cloud_provider='GCP')
        self.host_vulns_data=self.gather_host_vulnerability_data(vulns_start_time.generate_time_string(), vulns_end_time.generate_time_string())
        self.container_vulns_data=self.gather_container_vulnerability_data(vulns_start_time.generate_time_string(), vulns_end_time.generate_time_string())
        self.alerts_data=self.gather_alert_data(alerts_start_time.generate_time_string(), alerts_end_time.generate_time_string())
        self.secrets_data=self.gather_secrets(alerts_start_time.generate_time_string(), alerts_end_time.generate_time_string())
        self.ciem_data=self.gather_identity_entitlement_data(alerts_start_time.generate_time_string(), alerts_end_time.generate_time_string(), threshold=ciem_threshold)

    def render(self, customer, author, pagesize="a3", custom_logo=None, pdf=False):
        if custom_logo and os.path.isfile(custom_logo):
            self.custom_logo_html = self.file_to_image_tag(custom_logo, 'png', align='right')
        else:
            self.custom_logo_html = None
        self.template = self.get_jinja2_template('csa_detailed_report.jinja2')
        return self.template.render(
            customer=str(customer),
            date=self.get_current_date(),
            author=str(author),
            company_logo_html=self.company_logo_html,
            rca_logo_html=self.rca_logo_html,
            custom_logo_html=self.custom_logo_html,
            polygraph_graphic_html=self.polygraph_graphic_html,
            sec_outcomes_html=self.sec_outcomes_html,
            cloud_status_quo_html=self.cloud_status_quo_html,
            fortinet_sec_fabric_html=self.fortinet_sec_fabric_html,
            forticnapp_platform_html=self.forticnapp_platform_html,
            state_of_cloud_html=self.state_of_cloud_html,
            aws_compliance_data=self.aws_compliance_data,
            azure_compliance_data=self.azure_compliance_data,
            gcp_compliance_data=self.gcp_compliance_data,
            host_vulns_data=self.host_vulns_data,
            container_vulns_data=self.container_vulns_data,
            alerts_data=self.alerts_data,
            secrets_data=self.secrets_data,
            ciem_data=self.ciem_data,
            recommendations=self.recommendations,
            fortinet_resources_qr_html=self.fortinet_resources_qr_html,
            pagesize=pagesize,
            pdf=pdf
        )

    def generate(self,
                 customer: str,
                 author: str,
                 vulns_start_time: LaceworkTime = LaceworkTime('7:0'),
                 vulns_end_time: LaceworkTime = LaceworkTime('0:0'),
                 alerts_start_time: LaceworkTime = LaceworkTime('7:0'),
                 alerts_end_time: LaceworkTime = LaceworkTime('0:0'),
                 ciem_threshold: int = 70,
                 custom_logo=None,
                 pagesize="a3",
                 pdf=False):
        self.gather_data(vulns_start_time,
                         vulns_end_time,
                         alerts_start_time,
                         alerts_end_time,
                         ciem_threshold=ciem_threshold)
        return self.render(customer, author, custom_logo=custom_logo, pagesize=pagesize, pdf=pdf)


