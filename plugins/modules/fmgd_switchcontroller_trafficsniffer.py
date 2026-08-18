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
module: fmgd_switchcontroller_trafficsniffer
short_description: Configure FortiSwitch RSPAN/ERSPAN traffic sniffing parameters.
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
  switchcontroller_trafficsniffer:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      erspan_ip:
        aliases: ['erspan-ip']
        type: str
        description: Configure ERSPAN collector IP address.
      mode:
        type: str
        description: Configure traffic sniffer mode.
        choices: ['none', 'erspan-auto', 'rspan']
      target_ip:
        aliases: ['target-ip']
        type: list
        elements: dict
        description: Target ip.
        suboptions:
          description:
            type: str
            description: Description for the sniffer IP.
          ip:
            type: str
            description: Sniffer IP.
          src_entry_id:
            aliases: ['src-entry-id']
            type: int
            description: FortiSwitch source entry ID for the sniffer IP.
          dst_entry_id:
            aliases: ['dst-entry-id']
            type: int
            description: FortiSwitch dest entry ID for the sniffer IP.
      target_mac:
        aliases: ['target-mac']
        type: list
        elements: dict
        description: Target mac.
        suboptions:
          description:
            type: str
            description: Description for the sniffer MAC.
          mac:
            type: str
            description: Sniffer MAC.
          src_entry_id:
            aliases: ['src-entry-id']
            type: int
            description: FortiSwitch source entry ID for the sniffer MAC.
          dst_entry_id:
            aliases: ['dst-entry-id']
            type: int
            description: FortiSwitch dest entry ID for the sniffer MAC.
      target_port:
        aliases: ['target-port']
        type: list
        elements: dict
        description: Target port.
        suboptions:
          description:
            type: str
            description: Description for the sniffer port entry.
          in_ports:
            aliases: ['in-ports']
            type: list
            elements: str
            description: Configure source ingress port interfaces.
          out_ports:
            aliases: ['out-ports']
            type: list
            elements: str
            description: Configure source egress port interfaces.
          switch_id:
            aliases: ['switch-id']
            type: list
            elements: str
            description: Managed-switch ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch RSPAN/ERSPAN traffic sniffing parameters.
      fortinet.fmgdevice.fmgd_switchcontroller_trafficsniffer:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        switchcontroller_trafficsniffer:
          # erspan_ip: <string>
          # mode: <value in [none, erspan-auto, rspan]>
          # target_ip:
          #   - description: <string>
          #     ip: <string>
          #     src_entry_id: <integer>
          #     dst_entry_id: <integer>
          # target_mac:
          #   - description: <string>
          #     mac: <string>
          #     src_entry_id: <integer>
          #     dst_entry_id: <integer>
          # target_port:
          #   - description: <string>
          #     in_ports: <list or string>
          #     out_ports: <list or string>
          #     switch_id: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_trafficsniffer': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'erspan-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['none', 'erspan-auto', 'rspan'], 'type': 'str'},
                'target-ip': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'src-entry-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'dst-entry-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'target-mac': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'mac': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'src-entry-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'dst-entry-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'target-port': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'in-ports': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'out-ports': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'switch-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_trafficsniffer'),
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
