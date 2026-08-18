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
module: fmgd_system_sflow
short_description: Configure sFlow.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_sflow:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      collectors:
        type: list
        elements: dict
        description: Collectors.
        suboptions:
          collector_ip:
            aliases: ['collector-ip']
            type: str
            description: IP addresses of the sFlow collectors that sFlow agents added to interfaces in this VDOM send sFlow datagrams to.
          collector_port:
            aliases: ['collector-port']
            type: int
            description: UDP port number used for sending sFlow datagrams
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
            description: Source IP address for sFlow agent.
      collector_port:
        aliases: ['collector-port']
        type: int
        description: UDP port number used for sending sFlow datagrams
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address for sFlow agent.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      collector_ip:
        aliases: ['collector-ip']
        type: str
        description: IP address of the sFlow collector that sFlow agents added to interfaces in this VDOM send sFlow datagrams to
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure sFlow.
      fortinet.fmgdevice.fmgd_system_sflow:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_sflow:
          # collectors:
          #   - collector_ip: <string>
          #     collector_port: <integer>
          #     id: <integer>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, sdwan, specify]>
          #     source_ip: <string>
          # collector_port: <integer>
          # source_ip: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # collector_ip: <string>
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
        '/pm/config/device/{device}/global/system/sflow'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_sflow': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'collectors': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'collector-ip': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'collector-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                        'source-ip': {'v_range': [['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'collector-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'collector-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sflow'),
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
