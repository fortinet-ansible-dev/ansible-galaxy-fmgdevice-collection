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
module: fmgd_switchcontroller_stormcontrolpolicy
short_description: Configure FortiSwitch storm control policy to be applied on managed-switch ports.
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
  switchcontroller_stormcontrolpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      broadcast:
        type: str
        description: Enable/disable storm control to drop/allow broadcast traffic in override mode.
        choices: ['disable', 'enable']
      description:
        type: str
        description: Description of the storm control policy.
      name:
        type: str
        description: Storm control policy name.
        required: true
      rate:
        type: int
        description: Threshold rate in packets per second at which storm traffic is controlled in override mode
      storm_control_mode:
        aliases: ['storm-control-mode']
        type: str
        description: Set Storm control mode.
        choices: ['disabled', 'global', 'override']
      unknown_multicast:
        aliases: ['unknown-multicast']
        type: str
        description: Enable/disable storm control to drop/allow unknown multicast traffic in override mode.
        choices: ['disable', 'enable']
      unknown_unicast:
        aliases: ['unknown-unicast']
        type: str
        description: Enable/disable storm control to drop/allow unknown unicast traffic in override mode.
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
    - name: Configure FortiSwitch storm control policy to be applied on managed-switch ports.
      fortinet.fmgdevice.fmgd_switchcontroller_stormcontrolpolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_stormcontrolpolicy:
          name: "your value" # Required variable, string
          # broadcast: <value in [disable, enable]>
          # description: <string>
          # rate: <integer>
          # storm_control_mode: <value in [disabled, global, override]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/storm-control-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_stormcontrolpolicy': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'broadcast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'rate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'storm-control-mode': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disabled', 'global', 'override'], 'type': 'str'},
                'unknown-multicast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'unknown-unicast': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'burst-size-level': {'v_range': [['7.6.4', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_stormcontrolpolicy'),
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
