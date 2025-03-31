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
module: fmgd_log_fortianalyzer_setting
short_description: Global FortiAnalyzer settings.
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
    log_fortianalyzer_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            access_config:
                aliases: ['access-config']
                type: str
                description: Enable/disable FortiAnalyzer access to configuration and data.
                choices:
                    - 'disable'
                    - 'enable'
            alt_server:
                aliases: ['alt-server']
                type: str
                description: Alternate FortiAnalyzer.
            certificate:
                type: list
                elements: str
                description: Certificate used to communicate with FortiAnalyzer.
            certificate_verification:
                aliases: ['certificate-verification']
                type: str
                description: Enable/disable identity verification of FortiAnalyzer by use of certificate.
                choices:
                    - 'disable'
                    - 'enable'
            conn_timeout:
                aliases: ['conn-timeout']
                type: int
                description: FortiAnalyzer connection time-out in seconds
            enc_algorithm:
                aliases: ['enc-algorithm']
                type: str
                description: Configure the level of SSL protection for secure communication with FortiAnalyzer.
                choices:
                    - 'default'
                    - 'high'
                    - 'low'
                    - 'disable'
                    - 'high-medium'
                    - 'low-medium'
            fallback_to_primary:
                aliases: ['fallback-to-primary']
                type: str
                description: Enable/disable this FortiGate unit to fallback to the primary FortiAnalyzer when it is available.
                choices:
                    - 'disable'
                    - 'enable'
            hmac_algorithm:
                aliases: ['hmac-algorithm']
                type: str
                description: OFTP login hash algorithm.
                choices:
                    - 'sha256'
                    - 'sha1'
            interface:
                type: list
                elements: str
                description:
                    - Support meta variable
                    - Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            ips_archive:
                aliases: ['ips-archive']
                type: str
                description: Enable/disable IPS packet archive logging.
                choices:
                    - 'disable'
                    - 'enable'
            max_log_rate:
                aliases: ['max-log-rate']
                type: int
                description: FortiAnalyzer maximum log rate in MBps
            monitor_failure_retry_period:
                aliases: ['monitor-failure-retry-period']
                type: int
                description: Time between FortiAnalyzer connection retries in seconds
            monitor_keepalive_period:
                aliases: ['monitor-keepalive-period']
                type: int
                description: Time between OFTP keepalives in seconds
            preshared_key:
                aliases: ['preshared-key']
                type: str
                description: Preshared-key used for auto-authorization on FortiAnalyzer.
            priority:
                type: str
                description: Set log transmission priority.
                choices:
                    - 'low'
                    - 'default'
            reliable:
                type: str
                description: Enable/disable reliable logging to FortiAnalyzer.
                choices:
                    - 'disable'
                    - 'enable'
            server_cert_ca:
                aliases: ['server-cert-ca']
                type: list
                elements: str
                description: Mandatory CA on FortiGate in certificate chain of server.
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'default'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1-3'
            upload_day:
                aliases: ['upload-day']
                type: str
                description: Day of week
            upload_interval:
                aliases: ['upload-interval']
                type: str
                description: Frequency to upload log files to FortiAnalyzer.
                choices:
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            upload_option:
                aliases: ['upload-option']
                type: str
                description: Enable/disable logging to hard disk and then uploading to FortiAnalyzer.
                choices:
                    - 'store-and-upload'
                    - 'realtime'
                    - '1-minute'
                    - '5-minute'
            upload_time:
                aliases: ['upload-time']
                type: str
                description: Time to upload logs
            serial:
                type: list
                elements: str
                description: Serial numbers of the FortiAnalyzer.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IPv4 or IPv6 address used to communicate with FortiAnalyzer.
            status:
                type: str
                description: Enable/disable logging to FortiAnalyzer.
                choices:
                    - 'disable'
                    - 'enable'
            __change_ip:
                type: int
                description: Hidden attribute.
            server:
                type: str
                description: The remote FortiAnalyzer.
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
    - name: Global FortiAnalyzer settings.
      fortinet.fmgdevice.fmgd_log_fortianalyzer_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        log_fortianalyzer_setting:
          # access_config: <value in [disable, enable]>
          # alt_server: <string>
          # certificate: <list or string>
          # certificate_verification: <value in [disable, enable]>
          # conn_timeout: <integer>
          # enc_algorithm: <value in [default, high, low, ...]>
          # fallback_to_primary: <value in [disable, enable]>
          # hmac_algorithm: <value in [sha256, sha1]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ips_archive: <value in [disable, enable]>
          # max_log_rate: <integer>
          # monitor_failure_retry_period: <integer>
          # monitor_keepalive_period: <integer>
          # preshared_key: <string>
          # priority: <value in [low, default]>
          # reliable: <value in [disable, enable]>
          # server_cert_ca: <list or string>
          # ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # upload_day: <string>
          # upload_interval: <value in [daily, weekly, monthly]>
          # upload_option: <value in [store-and-upload, realtime, 1-minute, ...]>
          # upload_time: <string>
          # serial: <list or string>
          # source_ip: <string>
          # status: <value in [disable, enable]>
          # __change_ip: <integer>
          # server: <string>
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
        '/pm/config/device/{device}/global/log/fortianalyzer/setting'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'log_fortianalyzer_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'access-config': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'alt-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certificate-verification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'conn-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'enc-algorithm': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['default', 'high', 'low', 'disable', 'high-medium', 'low-medium'],
                    'type': 'str'
                },
                'fallback-to-primary': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hmac-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['sha256', 'sha1'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ips-archive': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-log-rate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'monitor-failure-retry-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'monitor-keepalive-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'preshared-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['low', 'default'], 'type': 'str'},
                'reliable': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-cert-ca': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'upload-day': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'upload-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['daily', 'weekly', 'monthly'], 'type': 'str'},
                'upload-option': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['store-and-upload', 'realtime', '1-minute', '5-minute'],
                    'type': 'str'
                },
                'upload-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'serial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '__change_ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_fortianalyzer_setting'),
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
