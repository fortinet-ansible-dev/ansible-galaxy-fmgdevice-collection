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
module: fmgd_ips_global
short_description: Configure IPS global parameter.
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
    ips_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            anomaly_mode:
                aliases: ['anomaly-mode']
                type: str
                description: Global blocking mode for rate-based anomalies.
                choices:
                    - 'periodical'
                    - 'continuous'
            av_mem_limit:
                aliases: ['av-mem-limit']
                type: int
                description: Maximum percentage of system memory allowed for use on AV scanning
            cp_accel_mode:
                aliases: ['cp-accel-mode']
                type: str
                description: IPS Pattern matching acceleration/offloading to CPx processors.
                choices:
                    - 'none'
                    - 'basic'
                    - 'advanced'
            database:
                type: str
                description: Regular or extended IPS database.
                choices:
                    - 'regular'
                    - 'extended'
            deep_app_insp_db_limit:
                aliases: ['deep-app-insp-db-limit']
                type: int
                description: Limit on number of entries in deep application inspection database
            deep_app_insp_timeout:
                aliases: ['deep-app-insp-timeout']
                type: int
                description: Timeout for Deep application inspection
            engine_count:
                aliases: ['engine-count']
                type: int
                description: Number of IPS engines running.
            exclude_signatures:
                aliases: ['exclude-signatures']
                type: str
                description: Excluded signatures.
                choices:
                    - 'none'
                    - 'industrial'
                    - 'ot'
            fail_open:
                aliases: ['fail-open']
                type: str
                description: Enable to allow traffic if the IPS buffer is full.
                choices:
                    - 'disable'
                    - 'enable'
            ips_reserve_cpu:
                aliases: ['ips-reserve-cpu']
                type: str
                description: Enable/disable IPS daemons use of CPUs other than CPU 0.
                choices:
                    - 'disable'
                    - 'enable'
            ngfw_max_scan_range:
                aliases: ['ngfw-max-scan-range']
                type: int
                description: NGFW policy-mode app detection threshold.
            np_accel_mode:
                aliases: ['np-accel-mode']
                type: str
                description: Acceleration mode for IPS processing by NPx processors.
                choices:
                    - 'none'
                    - 'basic'
            packet_log_queue_depth:
                aliases: ['packet-log-queue-depth']
                type: int
                description: Packet/pcap log queue depth per IPS engine.
            session_limit_mode:
                aliases: ['session-limit-mode']
                type: str
                description: Method of counting concurrent sessions used by session limit anomalies.
                choices:
                    - 'accurate'
                    - 'heuristic'
            socket_size:
                aliases: ['socket-size']
                type: int
                description: IPS socket buffer size.
            sync_session_ttl:
                aliases: ['sync-session-ttl']
                type: str
                description: Enable/disable use of kernel session TTL for IPS sessions.
                choices:
                    - 'disable'
                    - 'enable'
            tls_active_probe:
                aliases: ['tls-active-probe']
                type: dict
                description: Tls active probe.
                suboptions:
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
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Source IP address used for TLS active probe.
                    source_ip6:
                        aliases: ['source-ip6']
                        type: str
                        description: Source IPv6 address used for TLS active probe.
                    vdom:
                        type: list
                        elements: str
                        description: Virtual domain name for TLS active probe.
            traffic_submit:
                aliases: ['traffic-submit']
                type: str
                description: Enable/disable submitting attack data found by this FortiGate to FortiGuard.
                choices:
                    - 'disable'
                    - 'enable'
            intelligent_mode:
                aliases: ['intelligent-mode']
                type: str
                description: Enable/disable IPS adaptive scanning
                choices:
                    - 'disable'
                    - 'enable'
            skype_client_public_ipaddr:
                aliases: ['skype-client-public-ipaddr']
                type: str
                description: Public IP addresses of your network that receive Skype sessions.
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
    - name: Configure IPS global parameter.
      fortinet.fmgdevice.fmgd_ips_global:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        ips_global:
          # anomaly_mode: <value in [periodical, continuous]>
          # av_mem_limit: <integer>
          # cp_accel_mode: <value in [none, basic, advanced]>
          # database: <value in [regular, extended]>
          # deep_app_insp_db_limit: <integer>
          # deep_app_insp_timeout: <integer>
          # engine_count: <integer>
          # exclude_signatures: <value in [none, industrial, ot]>
          # fail_open: <value in [disable, enable]>
          # ips_reserve_cpu: <value in [disable, enable]>
          # ngfw_max_scan_range: <integer>
          # np_accel_mode: <value in [none, basic]>
          # packet_log_queue_depth: <integer>
          # session_limit_mode: <value in [accurate, heuristic]>
          # socket_size: <integer>
          # sync_session_ttl: <value in [disable, enable]>
          # tls_active_probe:
          #   interface: <list or string>
          #   interface_select_method: <value in [auto, sdwan, specify]>
          #   source_ip: <string>
          #   source_ip6: <string>
          #   vdom: <list or string>
          # traffic_submit: <value in [disable, enable]>
          # intelligent_mode: <value in [disable, enable]>
          # skype_client_public_ipaddr: <string>
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
        '/pm/config/device/{device}/global/ips/global'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'ips_global': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'anomaly-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['periodical', 'continuous'], 'type': 'str'},
                'av-mem-limit': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'cp-accel-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'basic', 'advanced'], 'type': 'str'},
                'database': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular', 'extended'], 'type': 'str'},
                'deep-app-insp-db-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'deep-app-insp-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'engine-count': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'exclude-signatures': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'industrial', 'ot'], 'type': 'str'},
                'fail-open': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-reserve-cpu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ngfw-max-scan-range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'np-accel-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'basic'], 'type': 'str'},
                'packet-log-queue-depth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'session-limit-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['accurate', 'heuristic'], 'type': 'str'},
                'socket-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sync-session-ttl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tls-active-probe': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'source-ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    }
                },
                'traffic-submit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'intelligent-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'skype-client-public-ipaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_global'),
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
