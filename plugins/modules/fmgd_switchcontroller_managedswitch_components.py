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
module: fmgd_switchcontroller_managedswitch_components
short_description: Managed-switch component list.
version_added: "1.2.0"
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
  managed-switch:
    description: Deprecated, please use "managed_switch"
    type: str
  managed_switch:
    description: The parameter (managed-switch) in requested url.
    type: str
  switchcontroller_managedswitch_components:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      admin_status:
        aliases: ['admin-status']
        type: str
        description: Managed-switch component admin-status.
        choices: ['disable', 'enable']
      capability:
        type: str
        description: Managed-switch feature capability list.
      component_id:
        aliases: ['component-id']
        type: int
        description: Managed-switch component id in stacking/chassis.
      description:
        type: str
        description: Managed-switch component description.
      dynamically_discovered:
        aliases: ['dynamically-discovered']
        type: int
        description: Dynamically discovered.
      max_allowed_trunk_members:
        aliases: ['max-allowed-trunk-members']
        type: int
        description: Managed-switch component maximum allowed trunk members.
      name:
        type: str
        description: Managed-switch component name.
        required: true
      poe_detection_type:
        aliases: ['poe-detection-type']
        type: int
        description: Managed-switch component PoE detection type.
      role:
        type: str
        description: Managed-switch components role.
        choices: ['None', 'Primary', 'Backup', 'Follower', 'Standalone']
      serial_number:
        aliases: ['serial-number']
        type: str
        description: Managed-switch component serial number.
      status:
        type: str
        description: Status.
        choices: ['offline', 'online']
      sw_version:
        aliases: ['sw-version']
        type: str
        description: Managed-switch component software version.
      switch_id:
        aliases: ['switch-id']
        type: str
        description: Switch id.
      type:
        type: str
        description: Managed-switch component type.
        choices: ['stack-node', 'supervisor', 'linecard']
      version:
        type: int
        description: Managed-switch component version.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Managed-switch component list.
      fortinet.fmgdevice.fmgd_switchcontroller_managedswitch_components:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        managed_switch: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch_components:
          name: "your value" # Required variable, string
          # admin_status: <value in [disable, enable]>
          # capability: <string>
          # component_id: <integer>
          # description: <string>
          # dynamically_discovered: <integer>
          # max_allowed_trunk_members: <integer>
          # poe_detection_type: <integer>
          # role: <value in [None, Primary, Backup, ...]>
          # serial_number: <string>
          # status: <value in [offline, online]>
          # sw_version: <string>
          # switch_id: <string>
          # type: <value in [stack-node, supervisor, linecard]>
          # version: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/components'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'switchcontroller_managedswitch_components': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {
                'admin-status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'capability': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'component-id': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'description': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'dynamically-discovered': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'max-allowed-trunk-members': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'name': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'str'},
                'poe-detection-type': {'v_range': [['8.0.0', '']], 'type': 'int'},
                'role': {'v_range': [['8.0.0', '']], 'choices': ['None', 'Primary', 'Backup', 'Follower', 'Standalone'], 'type': 'str'},
                'serial-number': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'status': {'v_range': [['8.0.0', '']], 'choices': ['offline', 'online'], 'type': 'str'},
                'sw-version': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'switch-id': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'type': {'v_range': [['8.0.0', '']], 'choices': ['stack-node', 'supervisor', 'linecard'], 'type': 'str'},
                'version': {'v_range': [['8.0.0', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_components'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
