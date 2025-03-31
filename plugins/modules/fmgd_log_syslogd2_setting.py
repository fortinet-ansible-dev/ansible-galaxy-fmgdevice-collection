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
module: fmgd_log_syslogd2_setting
short_description: Global settings for remote syslog server.
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
    log_syslogd2_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            certificate:
                type: list
                elements: str
                description: Certificate used to communicate with Syslog server.
            custom_field_name:
                aliases: ['custom-field-name']
                type: list
                elements: dict
                description: Custom field name.
                suboptions:
                    custom:
                        type: str
                        description: Field custom name [A-Za-z0-9_].
                    id:
                        type: int
                        description: Entry ID.
                    name:
                        type: str
                        description: Field name [A-Za-z0-9_].
            enc_algorithm:
                aliases: ['enc-algorithm']
                type: str
                description: Enable/disable reliable syslogging with TLS encryption.
                choices:
                    - 'high'
                    - 'low'
                    - 'disable'
                    - 'high-medium'
            facility:
                type: str
                description: Remote syslog facility.
                choices:
                    - 'kernel'
                    - 'user'
                    - 'mail'
                    - 'daemon'
                    - 'auth'
                    - 'syslog'
                    - 'lpr'
                    - 'news'
                    - 'uucp'
                    - 'cron'
                    - 'authpriv'
                    - 'ftp'
                    - 'ntp'
                    - 'audit'
                    - 'alert'
                    - 'clock'
                    - 'local0'
                    - 'local1'
                    - 'local2'
                    - 'local3'
                    - 'local4'
                    - 'local5'
                    - 'local6'
                    - 'local7'
            format:
                type: str
                description: Log format.
                choices:
                    - 'default'
                    - 'csv'
                    - 'cef'
                    - 'rfc5424'
                    - 'json'
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            max_log_rate:
                aliases: ['max-log-rate']
                type: int
                description: Syslog maximum log rate in MBps
            mode:
                type: str
                description: Remote syslog logging over UDP/Reliable TCP.
                choices:
                    - 'udp'
                    - 'legacy-reliable'
                    - 'reliable'
            port:
                type: int
                description: Server listen port.
            priority:
                type: str
                description: Set log transmission priority.
                choices:
                    - 'low'
                    - 'default'
            server:
                type: str
                description: Address of remote syslog server.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address of syslog.
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'default'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-3'
            status:
                type: str
                description: Enable/disable remote syslog logging.
                choices:
                    - 'disable'
                    - 'enable'
            source_ip_interface:
                aliases: ['source-ip-interface']
                type: list
                elements: str
                description: Source interface of syslog.
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: Global settings for remote syslog server.
      fortinet.fmgdevice.fmgd_log_syslogd2_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        log_syslogd2_setting:
          # certificate: <list or string>
          # custom_field_name:
          #   - custom: <string>
          #     id: <integer>
          #     name: <string>
          # enc_algorithm: <value in [high, low, disable, ...]>
          # facility: <value in [kernel, user, mail, ...]>
          # format: <value in [default, csv, cef, ...]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # max_log_rate: <integer>
          # mode: <value in [udp, legacy-reliable, reliable]>
          # port: <integer>
          # priority: <value in [low, default]>
          # server: <string>
          # source_ip: <string>
          # ssl_min_proto_version: <value in [default, TLSv1-1, TLSv1-2, ...]>
          # status: <value in [disable, enable]>
          # source_ip_interface: <list or string>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/global/log/syslogd2/setting'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'log_syslogd2_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'custom-field-name': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'custom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'enc-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['high', 'low', 'disable', 'high-medium'], 'type': 'str'},
                'facility': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert',
                        'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                    ],
                    'type': 'str'
                },
                'format': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'csv', 'cef', 'rfc5424', 'json'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'max-log-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['udp', 'legacy-reliable', 'reliable'], 'type': 'str'},
                'port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['low', 'default'], 'type': 'str'},
                'server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['default', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_syslogd2_setting'),
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
