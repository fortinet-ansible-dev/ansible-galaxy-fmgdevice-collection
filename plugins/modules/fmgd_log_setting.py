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
module: fmgd_log_setting
short_description: Configure general log settings.
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
    log_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            anonymization_hash:
                aliases: ['anonymization-hash']
                type: str
                description: User name anonymization hash salt.
            brief_traffic_format:
                aliases: ['brief-traffic-format']
                type: str
                description: Enable/disable brief format traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            custom_log_fields:
                aliases: ['custom-log-fields']
                type: list
                elements: str
                description: Custom fields to append to all log messages.
            daemon_log:
                aliases: ['daemon-log']
                type: str
                description: Enable/disable daemon logging.
                choices:
                    - 'disable'
                    - 'enable'
            expolicy_implicit_log:
                aliases: ['expolicy-implicit-log']
                type: str
                description: Enable/disable explicit proxy firewall implicit policy logging.
                choices:
                    - 'disable'
                    - 'enable'
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable extended traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            faz_override:
                aliases: ['faz-override']
                type: str
                description: Enable/disable override FortiAnalyzer settings.
                choices:
                    - 'disable'
                    - 'enable'
            fortiview_weekly_data:
                aliases: ['fortiview-weekly-data']
                type: str
                description: Enable/disable FortiView weekly data.
                choices:
                    - 'disable'
                    - 'enable'
            fwpolicy_implicit_log:
                aliases: ['fwpolicy-implicit-log']
                type: str
                description: Enable/disable implicit firewall policy logging.
                choices:
                    - 'disable'
                    - 'enable'
            fwpolicy6_implicit_log:
                aliases: ['fwpolicy6-implicit-log']
                type: str
                description: Enable/disable implicit firewall policy6 logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_in_allow:
                aliases: ['local-in-allow']
                type: str
                description: Enable/disable local-in-allow logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_in_deny_broadcast:
                aliases: ['local-in-deny-broadcast']
                type: str
                description: Enable/disable local-in-deny-broadcast logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_in_deny_unicast:
                aliases: ['local-in-deny-unicast']
                type: str
                description: Enable/disable local-in-deny-unicast logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_out:
                aliases: ['local-out']
                type: str
                description: Enable/disable local-out logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_out_ioc_detection:
                aliases: ['local-out-ioc-detection']
                type: str
                description: Enable/disable local-out traffic IoC detection.
                choices:
                    - 'disable'
                    - 'enable'
            log_policy_comment:
                aliases: ['log-policy-comment']
                type: str
                description: Enable/disable inserting policy comments into traffic logs.
                choices:
                    - 'disable'
                    - 'enable'
            log_user_in_upper:
                aliases: ['log-user-in-upper']
                type: str
                description: Enable/disable logs with user-in-upper.
                choices:
                    - 'disable'
                    - 'enable'
            long_live_session_stat:
                aliases: ['long-live-session-stat']
                type: str
                description: Enable/disable long-live-session statistics logging.
                choices:
                    - 'disable'
                    - 'enable'
            neighbor_event:
                aliases: ['neighbor-event']
                type: str
                description: Enable/disable neighbor event logging.
                choices:
                    - 'disable'
                    - 'enable'
            resolve_ip:
                aliases: ['resolve-ip']
                type: str
                description: Enable/disable adding resolved domain names to traffic logs if possible.
                choices:
                    - 'disable'
                    - 'enable'
            resolve_port:
                aliases: ['resolve-port']
                type: str
                description: Enable/disable adding resolved service names to traffic logs.
                choices:
                    - 'disable'
                    - 'enable'
            rest_api_get:
                aliases: ['rest-api-get']
                type: str
                description: Enable/disable REST API GET request logging.
                choices:
                    - 'disable'
                    - 'enable'
            rest_api_set:
                aliases: ['rest-api-set']
                type: str
                description: Enable/disable REST API POST/PUT/DELETE request logging.
                choices:
                    - 'disable'
                    - 'enable'
            syslog_override:
                aliases: ['syslog-override']
                type: str
                description: Enable/disable override Syslog settings.
                choices:
                    - 'disable'
                    - 'enable'
            user_anonymize:
                aliases: ['user-anonymize']
                type: str
                description: Enable/disable anonymizing user names in log messages.
                choices:
                    - 'disable'
                    - 'enable'
            log_invalid_packet:
                aliases: ['log-invalid-packet']
                type: str
                description: Enable/disable invalid packet traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            log_policy_name:
                aliases: ['log-policy-name']
                type: str
                description: Enable/disable inserting policy name into traffic logs.
                choices:
                    - 'disable'
                    - 'enable'
            extended_utm_log:
                aliases: ['extended-utm-log']
                type: str
                description: Enable/disable extended UTM logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_in_policy_log:
                aliases: ['local-in-policy-log']
                type: str
                description: Enable/disable local-in-policy logging.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure general log settings.
      fortinet.fmgdevice.fmgd_log_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        log_setting:
          # anonymization_hash: <string>
          # brief_traffic_format: <value in [disable, enable]>
          # custom_log_fields: <list or string>
          # daemon_log: <value in [disable, enable]>
          # expolicy_implicit_log: <value in [disable, enable]>
          # extended_log: <value in [disable, enable]>
          # faz_override: <value in [disable, enable]>
          # fortiview_weekly_data: <value in [disable, enable]>
          # fwpolicy_implicit_log: <value in [disable, enable]>
          # fwpolicy6_implicit_log: <value in [disable, enable]>
          # local_in_allow: <value in [disable, enable]>
          # local_in_deny_broadcast: <value in [disable, enable]>
          # local_in_deny_unicast: <value in [disable, enable]>
          # local_out: <value in [disable, enable]>
          # local_out_ioc_detection: <value in [disable, enable]>
          # log_policy_comment: <value in [disable, enable]>
          # log_user_in_upper: <value in [disable, enable]>
          # long_live_session_stat: <value in [disable, enable]>
          # neighbor_event: <value in [disable, enable]>
          # resolve_ip: <value in [disable, enable]>
          # resolve_port: <value in [disable, enable]>
          # rest_api_get: <value in [disable, enable]>
          # rest_api_set: <value in [disable, enable]>
          # syslog_override: <value in [disable, enable]>
          # user_anonymize: <value in [disable, enable]>
          # log_invalid_packet: <value in [disable, enable]>
          # log_policy_name: <value in [disable, enable]>
          # extended_utm_log: <value in [disable, enable]>
          # local_in_policy_log: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/setting'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'anonymization-hash': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'brief-traffic-format': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-log-fields': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'daemon-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'expolicy-implicit-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extended-log': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'faz-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiview-weekly-data': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fwpolicy-implicit-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fwpolicy6-implicit-log': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-in-allow': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-in-deny-broadcast': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-in-deny-unicast': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-out-ioc-detection': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-policy-comment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-user-in-upper': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'long-live-session-stat': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'neighbor-event': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'resolve-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'resolve-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rest-api-get': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rest-api-set': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'syslog-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-anonymize': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-invalid-packet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-policy-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extended-utm-log': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-in-policy-log': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_setting'),
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
