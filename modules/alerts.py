import re
import pandas as pd
from datetime import *

_IP_RE      = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_HOST_RE    = re.compile(r'bad\s+host\s+(\S+?)(?:\s+at\b|$)', re.IGNORECASE)
_ON_HOST_RE = re.compile(r'(?:running\s+on\s+host|on\s+host|from\s+host)\s+(\S+?)(?:\s|$)', re.IGNORECASE)
_PORT_RE    = re.compile(r'(?:at\s+port|on\s+port|port)\s+(\d{1,5})\b', re.IGNORECASE)

def _extract_host_from_description(description):
    """Return 'host:port' (or just host) extracted from alert description text."""
    if not description:
        return '—'

    host = None
    for pattern in (_HOST_RE, _ON_HOST_RE):
        m = pattern.search(description)
        if m:
            host = m.group(1).rstrip('.,;:')
            break
    if not host:
        m = _IP_RE.search(description)
        if m:
            host = m.group(1)

    if not host:
        return '—'

    m = _PORT_RE.search(description)
    if m:
        return f'{host}:{m.group(1)}'
    return host

_BAD_IP_TYPES = {
    'NewExternalClientBadIp', 'NewExternalClientBadIpConn',
    'NewExternalClientBadIpConnToVuln', 'NewExternalServerBadIp',
    'NewExternalServerBadIPConn', 'NewExternalServerBadIPConnFromVuln',
    'NewExternalClientBadDns', 'NewExternalServerBadDns',
    'NewExternalServerBadDNSConn', 'LoginFromBadSourceUsingCalltype',
    'GcpUserLoggedInFromBadSource', 'NewAzureUserLoggedInFromBadSource',
    'SuspiciousUserLoginMultiGEOs', 'SuspiciousUserFailedLogin',
}

# Risk category shown only when a bad host is present
_RISK_MAP = {
    # Malicious — active attacker / known-bad infrastructure
    'NewExternalClientBadIp':              'Malicious',
    'NewExternalClientBadIpConn':          'Malicious',
    'NewExternalClientBadIpConnToVuln':    'Malicious',
    'NewExternalServerBadIp':              'Malicious',
    'NewExternalServerBadIPConn':          'Malicious',
    'NewExternalServerBadIPConnFromVuln':  'Malicious',
    'NewExternalClientBadDns':             'Malicious',
    'NewExternalServerBadDns':             'Malicious',
    'NewExternalServerBadDNSConn':         'Malicious',
    'LoginFromBadSourceUsingCalltype':     'Malicious',
    'GcpUserLoggedInFromBadSource':        'Malicious',
    'NewAzureUserLoggedInFromBadSource':   'Malicious',
    'SuspiciousUserLoginMultiGEOs':        'Malicious',
    'SuspiciousUserFailedLogin':           'Malicious',
    'MaliciousFile':                       'Malicious',
    'SuspiciousApplicationLaunched':       'Malicious',
    'SuspiciousFile':                      'Malicious',
    'NewPrivilegeEscalation':              'Malicious',
    'UnauthorizedAPICall':                 'Malicious',
    # Negligent — misconfig or weak controls
    'SuccessfulConsoleLoginWithoutMFA':    'Negligent',
    'UsageOfRootAccount':                  'Negligent',
    'CloudTrailChanged':                   'Negligent',
    'CloudTrailDeleted':                   'Negligent',
    'CloudTrailStopped':                   'Negligent',
    'SecurityGroupChange':                 'Negligent',
    'NACLChange':                          'Negligent',
    'VPCChange':                           'Negligent',
    'S3BucketACLChanged':                  'Negligent',
    'S3BucketPolicyChanged':               'Negligent',
    'IAMPolicyChanged':                    'Negligent',
    'GCPIAMPolicyChanged':                 'Negligent',
    'CustomerMasterKeyDisabled':           'Negligent',
    'CustomerMasterKeyScheduledForDeletion': 'Negligent',
    'GCPKMSKeyVersionDestroyed':           'Negligent',
    'ProjectOwnershipAssignmentsChanged':  'Negligent',
    # Unauthorized — shadow IT / unsanctioned activity
    'NewService':                          'Unauthorized',
    'NewRegion':                           'Unauthorized',
    'NewAccount':                          'Unauthorized',
    'NewAwsUser':                          'Unauthorized',
    'NewGcpUser':                          'Unauthorized',
    'NewUser':                             'Unauthorized',
    'NewVPC':                              'Unauthorized',
    'NewS3Bucket':                         'Unauthorized',
    'NewExternalClientConn':               'Unauthorized',
    'NewExternalServerDns':                'Unauthorized',
    'NewExternalServerIp':                 'Unauthorized',
    'NewExternalClientIp':                 'Unauthorized',
    'NewAzureService':                     'Unauthorized',
    'NewAzureSubscription':                'Unauthorized',
    'GCPGCSBucketCreated':                 'Unauthorized',
    'NewGcpRegion':                        'Unauthorized',
    'NewGcpService':                       'Unauthorized',
}

event_short_to_long = {
    'AccessKeyDeleted': 'Access Key Deleted',
    'ApiFailedWithError': 'API Failed With Error',
    'AuditConfigurationChanged': 'Audit Configuration Changed',
    'AwsAccountFailedApi': 'Unexpected Change in AWS Api Error Volume',
    'AwsAccountGpuLaunch': 'Unexpected Change in AWS GPU Instance Launch Volume',
    'ChangedFile': 'Changed File Detected',
    'CloudActivityLogIngestionFailed': 'Cloud Activity Log Ingestion Failure Detected',
    'CloudStorageIAMPermissionChanged': 'Cloud Storage IAM Permission Changed',
    'CloudTrailChanged': 'CloudTrail Changed',
    'CloudTrailDeleted': 'CloudTrail Deleted',
    'CloudTrailStopped': 'CloudTrail Stopped',
    'ComplianceChanged': 'Compliance Changed',
    'ConfigServiceChange': 'Config Service Change',
    'CustomRoleChanged': 'Custom Role Changed',
    'CustomerMasterKeyDisabled': 'Customer Master Key Disabled',
    'CustomerMasterKeyScheduledForDeletion': 'Customer Master Key Scheduled for Deletion',
    'ExistingCveFixAvailable': 'Fix Available for Security Vulnerability',
    'ExistingCveNewInDatacenter': 'Known Security Vulnerability',
    'ExistingCveNewInRepo': 'Known Security Vulnerability Discovered In Repository',
    'ExistingCveSeverityEscalated': 'Severity escalated for Security Vulnerability',
    'ExistingHostCveFixAvailable': 'Fix Available for Security Vulnerability',
    'FailedConsoleLogin': 'Failed Console Login',
    'GCPFolderIAMPolicyChanged': 'Folder IAM Policy Changed',
    'GCPGCSBucketCreated': 'New Cloud Storage Bucket Created',
    'GCPIAMPolicyChanged': 'IAM Policy Changed',
    'GCPKMSKeyVersionDestroyed': 'Cloud KMS Key Version Destroyed',
    'GCPLogSinkModified': 'Cloud Logging Sink Modified',
    'GCPNewKMSKey': 'New Cloud KMS Key Created',
    'GCPNewKMSKeyIAMPolicy': 'Cloud KMS Key IAM Policy Modified',
    'GCPNewKMSKeyRing': 'New Cloud KMS Key Ring Created',
    'GCPOrganizationIAMPolicyChanged': 'Organization IAM Policy Changed',
    'GCPProjectIAMPolicyChanged': 'Project IAM Policy Changed',
    'GCPSAAccessKeyChanged': 'Service Account Key Changed',
    'GCPSACreated': 'A new Service Account has been created',
    'GCPVPCVPNCreated': 'New Cloud VPN Created',
    'GCPVPCVPNDeleted': 'Cloud VPN Deleted',
    'GcpApiFailedWithError': 'GCP API Failed With Error',
    'GcpServiceAccessedInRegion': 'GCP Service Accessed in Region',
    'GcpServiceAccountLoggedInFromSource': 'GCP Service Account Logged In From Source',
    'GcpUserAccessingRegion': 'GCP User Accessed Region',
    'GcpUserLoggedInFromBadSource': 'GCP User Logged In From Bad Source',
    'GcpUserLoggedInFromSource': 'GCP User Logged in from Source',
    'IAMAccessKeyChanged': 'IAM Access Key Changed',
    'IAMPolicyChanged': 'IAM Policy Changed',
    'KnownHostCveDiscovered': 'Known Security Vulnerability',
    'LoginFromBadSourceUsingCalltype': 'Login From New Bad Source Using Calltype',
    'LoginFromSourceUsingCalltype': 'Login From Source Using Calltype',
    'MaliciousFile': 'Malicious File',
    'NACLChange': 'NACL Change',
    'NetworkGatewayChange': 'Network Gateway Change',
    'NetworkSecurityGroupCreatedOrUpdated': 'Network Security Group Created Or Updated',
    'NetworkSecurityGroupDeleted': 'Network Security Group Deleted',
    'NetworkSecurityGroupRuleCreatedOrUpdated': 'Network Security Group Rule Created Or Updated',
    'NetworkSecurityGroupRuleDeleted': 'Network Security Group Rule Deleted',
    'NewAccessKey': 'New Access Key',
    'NewAccount': 'New AWS Account',
    'NewAwsUser': 'New AWS User',
    'NewAzureApiCallOnResource': 'New Azure API Call Invoked by User Accessed Resource for the First Time',
    'NewAzureApiFailedWithError': 'New Azure API Failed With Error',
    'NewAzureService': 'New Azure SP Accessing Resource',
    'NewAzureSubscription': 'New Azure Subscription Created',
    'NewAzureUserEventCategory': 'New Azure User Performed Operation on Resource for the First Time',
    'NewAzureUserLoggedInFromBadSource': 'New Azure User Logged In From Bad Source',
    'NewBinaryType': 'New Application',
    'NewChildLaunched': 'New Child Launched',
    'NewChildLaunchedFromVulnParent': 'New Child Launched From Vulnerable Application',
    'NewCustomerMasterKey': 'New Customer Master Key',
    'NewCustomerMasterKeyAlias': 'New Customer Master Key Alias)',
    'NewCveDiscovered': 'New Security Vulnerability',
    'NewExternalClientBadDns': 'Bad External Client DNS',
    'NewExternalClientBadIp': 'Real-Time Bad External Client IP Address',
    'NewExternalClientBadIpConn': 'Bad External Client IP Address Connection',
    'NewExternalClientBadIpConnToVuln': 'Bad External Client IP Address Connection To Vulnerable Application',
    'NewExternalClientConn': 'New External Client IP Address Connection',
    'NewExternalClientDns': 'New External Client DNS',
    'NewExternalClientIp': 'New External Client IP Address',
    'NewExternalClientIpConnToVuln': 'New External Client IP Address Connection To Vulnerable Application',
    'NewExternalServerBadDNSConn': 'Bad External Server Host Connection',
    'NewExternalServerBadDns': 'Real-Time Bad External Server Host',
    'NewExternalServerBadIPConn': 'Bad External Server IP Address Connection',
    'NewExternalServerBadIPConnFromVuln': 'Bad External Server IP Address Connection From Vulnerable Application',
    'NewExternalServerBadIp': 'Real-Time Bad External Server IP Address',
    'NewExternalServerDNSConn': 'New External Server Host Connection',
    'NewExternalServerDNSConnFromVuln': 'New External Host Server Connection From Vulnerable Application',
    'NewExternalServerDns': 'New External Host',
    'NewExternalServerIPConn': 'New External Server IP Address Connection',
    'NewExternalServerIPConnFromVuln': 'New External Server IP Address Connection From Vulnerable Application',
    'NewExternalServerIp': 'New External Server IP Address',
    'NewGcpApiCall': 'New GCP API Call',
    'NewGcpOrganization': 'New GCP Organization',
    'NewGcpRegion': 'New GCP Region',
    'NewGcpService': 'New GCP Service',
    'NewGcpSource': 'New GCP Source',
    'NewGcpSourceForServiceAccount': 'New GCP Source For Service Account',
    'NewGcpUser': 'New GCP User',
    'NewGrantAddedToCustomerMasterKey': 'New Grant Added To Customer Master Key',
    'NewHostCveDiscovered': 'New Security Vulnerability',
    'NewInternalConnection': 'New Internal Connection',
    'NewK8Cluster': 'New K8s Cluster',
    'NewK8Namespace': 'New K8s Namespace',
    'NewK8Pod': 'New K8s Pod',
    'NewK8sAuditLogClusterRole': 'K8s Audit Log Cluster Role Created',
    'NewK8sAuditLogClusterRoleBinding': 'K8s Audit Log Cluster Role Binding Created',
    'NewK8sAuditLogClusterRoleBindingsToAdmin': 'K8s Audit Log Cluster Role Bindings To Admin',
    'NewK8sAuditLogClusterRoleBindingsToClusterAdmin': 'K8s Audit Log Cluster Role Bindings To Cluster Admin',
    'NewK8sAuditLogClusterRoleBindingsToEdit': 'K8s Audit Log Cluster Role Bindings To Edit',
    'NewK8sAuditLogClusterRoleBindingsToSystem': 'K8s Audit Log Cluster Role Bindings To System',
    'NewK8sAuditLogClusterRoleWithAllResources': 'K8s Audit Log Cluster Role With All Resources',
    'NewK8sAuditLogClusterRoleWithPodExec': 'K8s Audit Log Cluster Role With Pod Exec',
    'NewK8sAuditLogClusterRoleWithPodsWrite': 'K8s Audit Log Cluster Role With Pods Write',
    'NewK8sAuditLogClusterRoleWithSecrets': 'K8s Audit Log Cluster Role With Secrets',
    'NewK8sAuditLogIngress': 'K8s Audit Log Ingress Created',
    'NewK8sAuditLogNamespace': 'K8s Audit Log Namespace Created',
    'NewK8sAuditLogResource': 'K8s Audit Log Resource Created',
    'NewK8sAuditLogRole': 'K8s Audit Log Role Created',
    'NewK8sAuditLogRoleBinding': 'K8s Audit Log Role Binding Created',
    'NewK8sAuditLogRoleBindingsToAdmin': 'K8s Audit Log Role Bindings To Admin',
    'NewK8sAuditLogRoleBindingsToClusterAdmin': 'K8s Audit Log Role Bindings To Cluster Admin',
    'NewK8sAuditLogRoleBindingsToEdit': 'K8s Audit Log Role Bindings To Edit',
    'NewK8sAuditLogRoleBindingsToSystem': 'K8s Audit Log Role Bindings To System',
    'NewK8sAuditLogRoleWithAllResources': 'K8s Audit Log Role With All Resources',
    'NewK8sAuditLogRoleWithPodExec': 'K8s Audit Log Role With Pod Exec',
    'NewK8sAuditLogRoleWithPodsWrite': 'K8s Audit Log Role With Pods Write',
    'NewK8sAuditLogRoleWithSecrets': 'K8s Audit Log Role With Secrets',
    'NewK8sAuditLogWorkload': 'K8s Audit Log Workload Created',
    'NewK8sAuditLogWorkloadAllowsEscalation': 'New K8s Workload Created With Privilege Escalation',
    'NewK8sAuditLogWorkloadWithHostAccess': 'New K8s Workload Created With Host Access',
    'NewPrivilegeEscalation': 'New Privilege Escalation',
    'NewRegion': 'New Region',
    'NewS3Bucket': 'New S3 Bucket',
    'NewService': 'New Service',
    'NewUser': 'New AWS User',
    'NewVPC': 'New VPC',
    'NewVPNConnection': 'New VPN Connection',
    'NewViolations': 'New Violations',
    'NewVulnChildLaunched': 'New Vulnerable Child Launched',
    'NewVulnInternalConnection': 'New Vulnerable Internal Connection',
    'PolicyAssignmentCreated': 'Policy Assignment Created',
    'ProjectOwnershipAssignmentsChanged': 'Project Ownership Assignments Changed',
    'RouteTableChange': 'Route Table Change',
    'S3BucketACLChanged': 'S3 Bucket ACL Changed',
    'S3BucketDeleted': 'S3 Bucket Deleted',
    'S3BucketPolicyChanged': 'S3 Bucket Policy Changed',
    'SQLInstanceConfigurationChanged': 'SQL Instance Configuration Changed',
    'SQLServerFirewallRuleCreatedOrUpdated': 'SQL Server Firewall Rule Created Or Updated',
    'SQLServerFirewallRuleDeleted': 'SQL Server Firewall Rule Deleted',
    'SecurityGroupChange': 'Security Group Change',
    'SecurityPolicyUpdated': 'Security Policy Updated',
    'SecuritySolutionCreatedOrUpdated': 'Security Solution Created Or Updated',
    'SecuritySolutionDeleted': 'Security Solution Deleted',
    'ServiceAccessedInRegion': 'Service Accessed In Region',
    'ServiceCalledApi': 'Service Called API',
    'ServiceCalledGcpApi': 'Service called GCP API',
    'SuccessfulConsoleLoginWithoutMFA': 'Successful Console Login Without MFA',
    'SuspiciousApplicationLaunched': 'Suspicious Application Launched',
    'SuspiciousFile': 'Suspicious File Detected',
    'SuspiciousUserFailedLogin': 'Suspicious User Login Detected',
    'SuspiciousUserLoginMultiGEOs': 'Detect Suspicious User Logins',
    'UnauthorizedAPICall': 'Unauthorized API Call',
    'UsageOfRootAccount': 'Usage of Root account',
    'UserCalltypeMfa': 'User Calltype MFA',
    'UserLaunchedNewBinary': 'User Launched New Binary',
    'UserLaunchedNewVulnBinary': 'User Launched New Vulnerable Binary',
    'UserLoggedInFromNewLocation': 'User Logged in from New Location',
    'UserUsedServiceInRegion': 'User Used Service In Region',
    'VPCChange': 'VPC Change',
    'VPCNetworkChanged': 'VPC Network Changed',
    'VPCNetworkFirewallRuleChanged': 'VPC Network Firewall Rule Changed',
    'VPCNetworkRouteChanged': 'VPC Network Route Changed',
    'VPNGatewayChange': 'VPN Gateway Change'
}


class Alerts:

    def __init__(self, raw_data):
        self.data = raw_data

    def count_alerts(self):
        return len(self.data)

    def processed_alerts(self,
                         severities=("Critical",),
                         excluded_alert_types=("CloudTrailDefaultAlert", "CloudActivityLogIngestionFailed", "NewViolations", "ComplianceChanged"),
                         limit=False, detailed=True):

        processed_data = []
        for item in self.data:
            alert_info = item.get('alertInfo', {})
            alert_type = item.get('alertType', '')
            description = alert_info.get('description', '')

            # Extract bad host + port: subject field first, then parse description
            bad_host = alert_info.get('subject') or _extract_host_from_description(description) or '—'
            reputation = 'Bad IP' if alert_type in _BAD_IP_TYPES else '—'
            risk = _RISK_MAP.get(alert_type, '—') if bad_host != '—' else '—'

            processed_data.append({
                'alertId':    item['alertId'],
                'alertName':  item['alertName'],
                'startTime':  item['startTime'],
                'severity':   item['severity'],
                'description': description,
                'alertType':  alert_type,
                'badHost':    bad_host or '—',
                'reputation': reputation,
                'risk':       risk,
            })

        df = pd.DataFrame(processed_data)
        if 'alertType' in df:
            df = df[~df['alertType'].isin(excluded_alert_types)]
            df['severity'] = pd.Categorical(df['severity'], ["Critical", "High", "Medium", "Low", "Info"])
            df = df.sort_values(by=['severity', 'startTime'], ascending=[True, False])
            df = df[df['severity'].isin(severities)]
            df['startTime'] = df['startTime'].apply(
                lambda x: datetime.fromisoformat(x.replace("Z", "+00:00")).strftime("%B %d, %Y %I:%M%p"))
            df.rename(columns={
                'alertId': 'Alert ID', 'severity': 'Severity', 'startTime': 'Alert Time',
                'alertName': 'Alert Name', 'description': 'Description',
                'risk': 'IP or Domain Reputation',
            }, inplace=True)
            if detailed:
                df = df[['Alert ID', 'Severity', 'Alert Time', 'Alert Name', 'alertType',
                          'IP or Domain Reputation', 'Description']]
                df.rename(columns={'alertType': 'Alert Type'}, inplace=True)
            else:
                df = df[['Alert ID', 'Severity', 'Alert Time', 'Alert Name',
                          'IP or Domain Reputation']]
            if limit:
                df = df.head(limit)
        return df