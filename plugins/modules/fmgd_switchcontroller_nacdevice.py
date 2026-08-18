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
module: fmgd_switchcontroller_nacdevice
short_description: Configure/list NAC devices learned on the managed FortiSwitch ports which matches NAC policy.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  switchcontroller_nacdevice:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      description:
        type: str
        description: Description for the learned NAC device.
      entry_id:
        aliases: ['entry-id']
        type: int
        description: FSW entry id for the NAC device.
      id:
        type: int
        description: Device ID.
        required: true
      last_known_port:
        aliases: ['last-known-port']
        type: str
        description: Managed FortiSwitch port where NAC device is last learned.
      last_known_switch:
        aliases: ['last-known-switch']
        type: list
        elements: str
        description: Managed FortiSwitch where NAC device is last learned.
      last_seen:
        aliases: ['last-seen']
        type: int
        description: Last seen.
      mac:
        type: str
        description: MAC address of the learned NAC device.
      mac_policy:
        aliases: ['mac-policy']
        type: list
        elements: str
        description: MAC policy to be applied on this learned NAC device.
      matched_nac_policy:
        aliases: ['matched-nac-policy']
        type: list
        elements: str
        description: Matched NAC policy for the learned NAC device.
      port_policy:
        aliases: ['port-policy']
        type: list
        elements: str
        description: Port policy to be applied on this learned NAC device.
      status:
        type: str
        description: Status of the learned NAC device.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure/list NAC devices learned on the managed FortiSwitch ports which matches NAC policy.
      fortinet.fmgdevice.fmgd_switchcontroller_nacdevice:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_nacdevice:
          id: 0 # Required variable, integer
          # description: <string>
          # entry_id: <integer>
          # last_known_port: <string>
          # last_known_switch: <list or string>
          # last_seen: <integer>
          # mac: <string>
          # mac_policy: <list or string>
          # matched_nac_policy: <list or string>
          # port_policy: <list or string>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-device'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_nacdevice': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'entry-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'required': True, 'type': 'int'},
                'last-known-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'last-known-switch': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'last-seen': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'mac': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'mac-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'matched-nac-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'port-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_nacdevice'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'id', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
