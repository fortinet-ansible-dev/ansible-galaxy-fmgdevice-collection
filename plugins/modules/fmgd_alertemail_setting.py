#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgd_alertemail_setting
short_description: Configure alert email settings.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    alertemail_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            FDS_license_expiring_warning:
                aliases: ['FDS-license-expiring-warning']
                type: str
                description: Enable/disable FortiGuard license expiration warnings in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            FDS_update_logs:
                aliases: ['FDS-update-logs']
                type: str
                description: Enable/disable FortiGuard update logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            FIPS_CC_errors:
                aliases: ['FIPS-CC-errors']
                type: str
                description: Enable/disable FIPS and Common Criteria error logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            FSSO_disconnect_logs:
                aliases: ['FSSO-disconnect-logs']
                type: str
                description: Enable/disable logging of FSSO collector agent disconnect.
                choices:
                    - 'disable'
                    - 'enable'
            HA_logs:
                aliases: ['HA-logs']
                type: str
                description: Enable/disable HA logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            IPS_logs:
                aliases: ['IPS-logs']
                type: str
                description: Enable/disable IPS logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            IPsec_errors_logs:
                aliases: ['IPsec-errors-logs']
                type: str
                description: Enable/disable IPsec error logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            PPP_errors_logs:
                aliases: ['PPP-errors-logs']
                type: str
                description: Enable/disable PPP error logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            admin_login_logs:
                aliases: ['admin-login-logs']
                type: str
                description: Enable/disable administrator login/logout logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            alert_interval:
                aliases: ['alert-interval']
                type: int
                description: Alert alert interval in minutes.
            amc_interface_bypass_mode:
                aliases: ['amc-interface-bypass-mode']
                type: str
                description: Enable/disable Fortinet Advanced Mezzanine Card
                choices:
                    - 'disable'
                    - 'enable'
            antivirus_logs:
                aliases: ['antivirus-logs']
                type: str
                description: Enable/disable antivirus logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            configuration_changes_logs:
                aliases: ['configuration-changes-logs']
                type: str
                description: Enable/disable configuration change logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            critical_interval:
                aliases: ['critical-interval']
                type: int
                description: Critical alert interval in minutes.
            debug_interval:
                aliases: ['debug-interval']
                type: int
                description: Debug alert interval in minutes.
            email_interval:
                aliases: ['email-interval']
                type: int
                description: Interval between sending alert emails
            emergency_interval:
                aliases: ['emergency-interval']
                type: int
                description: Emergency alert interval in minutes.
            error_interval:
                aliases: ['error-interval']
                type: int
                description: Error alert interval in minutes.
            filter_mode:
                aliases: ['filter-mode']
                type: str
                description: How to filter log messages that are sent to alert emails.
                choices:
                    - 'category'
                    - 'threshold'
            firewall_authentication_failure_logs:
                aliases: ['firewall-authentication-failure-logs']
                type: str
                description: Enable/disable firewall authentication failure logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            fortiguard_log_quota_warning:
                aliases: ['fortiguard-log-quota-warning']
                type: str
                description: Enable/disable FortiCloud log quota warnings in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            information_interval:
                aliases: ['information-interval']
                type: int
                description: Information alert interval in minutes.
            local_disk_usage:
                aliases: ['local-disk-usage']
                type: int
                description: Disk usage percentage at which to send alert email
            log_disk_usage_warning:
                aliases: ['log-disk-usage-warning']
                type: str
                description: Enable/disable disk usage warnings in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            mailto1:
                type: str
                description: Email address to send alert email to
            mailto2:
                type: str
                description: Optional second email address to send alert email to
            mailto3:
                type: str
                description: Optional third email address to send alert email to
            notification_interval:
                aliases: ['notification-interval']
                type: int
                description: Notification alert interval in minutes.
            severity:
                type: str
                description: Lowest severity level to log.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            ssh_logs:
                aliases: ['ssh-logs']
                type: str
                description: Enable/disable SSH logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_authentication_errors_logs:
                aliases: ['sslvpn-authentication-errors-logs']
                type: str
                description: Enable/disable SSL-VPN authentication error logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            username:
                type: str
                description: Name that appears in the From
            violation_traffic_logs:
                aliases: ['violation-traffic-logs']
                type: str
                description: Enable/disable violation traffic logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            warning_interval:
                aliases: ['warning-interval']
                type: int
                description: Warning alert interval in minutes.
            webfilter_logs:
                aliases: ['webfilter-logs']
                type: str
                description: Enable/disable web filter logs in alert email.
                choices:
                    - 'disable'
                    - 'enable'
            FDS_license_expiring_days:
                aliases: ['FDS-license-expiring-days']
                type: int
                description: Number of days to send alert email prior to FortiGuard license expiration
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure alert email settings.
      fortinet.fmgdevice.fmgd_alertemail_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        alertemail_setting:
          # FDS_license_expiring_warning: <value in [disable, enable]>
          # FDS_update_logs: <value in [disable, enable]>
          # FIPS_CC_errors: <value in [disable, enable]>
          # FSSO_disconnect_logs: <value in [disable, enable]>
          # HA_logs: <value in [disable, enable]>
          # IPS_logs: <value in [disable, enable]>
          # IPsec_errors_logs: <value in [disable, enable]>
          # PPP_errors_logs: <value in [disable, enable]>
          # admin_login_logs: <value in [disable, enable]>
          # alert_interval: <integer>
          # amc_interface_bypass_mode: <value in [disable, enable]>
          # antivirus_logs: <value in [disable, enable]>
          # configuration_changes_logs: <value in [disable, enable]>
          # critical_interval: <integer>
          # debug_interval: <integer>
          # email_interval: <integer>
          # emergency_interval: <integer>
          # error_interval: <integer>
          # filter_mode: <value in [category, threshold]>
          # firewall_authentication_failure_logs: <value in [disable, enable]>
          # fortiguard_log_quota_warning: <value in [disable, enable]>
          # information_interval: <integer>
          # local_disk_usage: <integer>
          # log_disk_usage_warning: <value in [disable, enable]>
          # mailto1: <string>
          # mailto2: <string>
          # mailto3: <string>
          # notification_interval: <integer>
          # severity: <value in [emergency, alert, critical, ...]>
          # ssh_logs: <value in [disable, enable]>
          # sslvpn_authentication_errors_logs: <value in [disable, enable]>
          # username: <string>
          # violation_traffic_logs: <value in [disable, enable]>
          # warning_interval: <integer>
          # webfilter_logs: <value in [disable, enable]>
          # FDS_license_expiring_days: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/device/{device}/vdom/{vdom}/alertemail/setting'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'alertemail_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'FDS-license-expiring-warning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'FDS-update-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'FIPS-CC-errors': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'FSSO-disconnect-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'HA-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'IPS-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'IPsec-errors-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'PPP-errors-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'admin-login-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'alert-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'amc-interface-bypass-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'antivirus-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'configuration-changes-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'critical-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'debug-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'email-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'emergency-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'error-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'filter-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['category', 'threshold'], 'type': 'str'},
                'firewall-authentication-failure-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiguard-log-quota-warning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'information-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'local-disk-usage': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'log-disk-usage-warning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mailto1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mailto2': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mailto3': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'notification-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'severity': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'ssh-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-authentication-errors-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'violation-traffic-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'warning-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'webfilter-logs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'FDS-license-expiring-days': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'alertemail_setting'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
