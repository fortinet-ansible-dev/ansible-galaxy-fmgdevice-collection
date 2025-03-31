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
module: fmgd_system_netflow
short_description: Configure NetFlow.
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
    system_netflow:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            active_flow_timeout:
                aliases: ['active-flow-timeout']
                type: int
                description: Timeout to report active flows
            collector_ip:
                aliases: ['collector-ip']
                type: str
                description: Collector IP.
            collector_port:
                aliases: ['collector-port']
                type: int
                description: NetFlow collector port number.
            collectors:
                type: list
                elements: dict
                description: Collectors.
                suboptions:
                    collector_ip:
                        aliases: ['collector-ip']
                        type: str
                        description: Collector IP.
                    collector_port:
                        aliases: ['collector-port']
                        type: int
                        description: NetFlow collector port number.
                    id:
                        type: int
                        description: ID.
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
                        description: Source IP address for communication with the NetFlow agent.
                    source_ip_interface:
                        aliases: ['source-ip-interface']
                        type: list
                        elements: str
                        description: Name of the interface used to determine the source IP for exporting packets.
                    vrf_select:
                        aliases: ['vrf-select']
                        type: int
                        description: VRF ID used for connection to server.
            inactive_flow_timeout:
                aliases: ['inactive-flow-timeout']
                type: int
                description: Timeout for periodic report of finished flows
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
                description: Source IP address for communication with the NetFlow agent.
            template_tx_counter:
                aliases: ['template-tx-counter']
                type: int
                description: Counter of flowset records before resending a template flowset record.
            template_tx_timeout:
                aliases: ['template-tx-timeout']
                type: int
                description: Timeout for periodic template flowset transmission
            exclusion_filters:
                aliases: ['exclusion-filters']
                type: list
                elements: dict
                description: Exclusion filters.
                suboptions:
                    destination_ip:
                        aliases: ['destination-ip']
                        type: str
                        description: Session destination address.
                    destination_port:
                        aliases: ['destination-port']
                        type: str
                        description: Session destination port number or range.
                    id:
                        type: int
                        description: Filter ID.
                    protocol:
                        type: int
                        description: Session IP protocol
                    source_ip:
                        aliases: ['source-ip']
                        type: str
                        description: Session source address.
                    source_port:
                        aliases: ['source-port']
                        type: str
                        description: Session source port number or range.
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
    - name: Configure NetFlow.
      fortinet.fmgdevice.fmgd_system_netflow:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_netflow:
          # active_flow_timeout: <integer>
          # collector_ip: <string>
          # collector_port: <integer>
          # collectors:
          #   - collector_ip: <string>
          #     collector_port: <integer>
          #     id: <integer>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, sdwan, specify]>
          #     source_ip: <string>
          #     source_ip_interface: <list or string>
          #     vrf_select: <integer>
          # inactive_flow_timeout: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # source_ip: <string>
          # template_tx_counter: <integer>
          # template_tx_timeout: <integer>
          # exclusion_filters:
          #   - destination_ip: <string>
          #     destination_port: <string>
          #     id: <integer>
          #     protocol: <integer>
          #     source_ip: <string>
          #     source_port: <string>
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
        '/pm/config/device/{device}/global/system/netflow'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_netflow': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'active-flow-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'collector-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'collector-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'collectors': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'collector-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'collector-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'source-ip-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                        'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'inactive-flow-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'template-tx-counter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'template-tx-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'exclusion-filters': {
                    'v_range': [['7.6.0', '']],
                    'type': 'list',
                    'options': {
                        'destination-ip': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'destination-port': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'id': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'protocol': {'v_range': [['7.6.0', '']], 'type': 'int'},
                        'source-ip': {'v_range': [['7.6.0', '']], 'type': 'str'},
                        'source-port': {'v_range': [['7.6.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_netflow'),
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
