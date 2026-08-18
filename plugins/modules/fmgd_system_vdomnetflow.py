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
module: fmgd_system_vdomnetflow
short_description: Configure NetFlow per VDOM.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  system_vdomnetflow:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      collector_ip:
        aliases: ['collector-ip']
        type: str
        description: NetFlow collector IP address.
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
            choices: ['auto', 'sdwan', 'specify']
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
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address for communication with the NetFlow agent.
      vdom_netflow:
        aliases: ['vdom-netflow']
        type: str
        description: Enable/disable NetFlow per VDOM.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure NetFlow per VDOM.
      fortinet.fmgdevice.fmgd_system_vdomnetflow:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        system_vdomnetflow:
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
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # source_ip: <string>
          # vdom_netflow: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/vdom-netflow'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_vdomnetflow': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'collector-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'collector-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'collectors': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'collector-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'collector-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'source-ip-interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                        'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'vdom-netflow': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vdomnetflow'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
