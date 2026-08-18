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
module: fmgd_switchcontroller_managedswitch_stormcontrol
short_description: Configuration method to edit FortiSwitch storm control for measuring traffic activity using data rates to prevent traffic disruption.
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
  managed-switch:
    description: Deprecated, please use "managed_switch"
    type: str
  managed_switch:
    description: The parameter (managed-switch) in requested url.
    type: str
  switchcontroller_managedswitch_stormcontrol:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      broadcast:
        type: str
        description: Enable/disable storm control to drop broadcast traffic.
        choices: ['disable', 'enable']
      local_override:
        aliases: ['local-override']
        type: str
        description: Enable to override global FortiSwitch storm control settings for this FortiSwitch.
        choices: ['disable', 'enable']
      rate:
        type: int
        description: Rate in packets per second at which storm control drops excess traffic
      unknown_multicast:
        aliases: ['unknown-multicast']
        type: str
        description: Enable/disable storm control to drop unknown multicast traffic.
        choices: ['disable', 'enable']
      unknown_unicast:
        aliases: ['unknown-unicast']
        type: str
        description: Enable/disable storm control to drop unknown unicast traffic.
        choices: ['disable', 'enable']
      burst_size_level:
        aliases: ['burst-size-level']
        type: int
        description: Increase level to handle bursty traffic
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configuration method to edit FortiSwitch storm control for measuring traffic activity using data rates to prevent traffic disruption.
      fortinet.fmgdevice.fmgd_switchcontroller_managedswitch_stormcontrol:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        managed_switch: <your own value>
        switchcontroller_managedswitch_stormcontrol:
          # broadcast: <value in [disable, enable]>
          # local_override: <value in [disable, enable]>
          # rate: <integer>
          # unknown_multicast: <value in [disable, enable]>
          # unknown_unicast: <value in [disable, enable]>
          # burst_size_level: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/storm-control'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'managed-switch': {'type': 'str', 'api_name': 'managed_switch'},
        'managed_switch': {'type': 'str'},
        'switchcontroller_managedswitch_stormcontrol': {
            'type': 'dict', 'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'broadcast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-override': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'unknown-multicast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-unicast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'burst-size-level': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch_stormcontrol'),
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
