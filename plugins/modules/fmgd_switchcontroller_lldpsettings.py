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
module: fmgd_switchcontroller_lldpsettings
short_description: Configure FortiSwitch LLDP settings.
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
  switchcontroller_lldpsettings:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      device_detection:
        aliases: ['device-detection']
        type: str
        description: Enable/disable dynamic detection of LLDP neighbor devices for VLAN assignment.
        choices: ['disable', 'enable']
      fast_start_interval:
        aliases: ['fast-start-interval']
        type: int
        description: Frequency of LLDP PDU transmission from FortiSwitch for the first 4 packets when the link is up
      management_interface:
        aliases: ['management-interface']
        type: str
        description: Primary management interface to be advertised in LLDP and CDP PDUs.
        choices: ['internal', 'mgmt']
      tx_hold:
        aliases: ['tx-hold']
        type: int
        description: Number of tx-intervals before local LLDP data expires
      tx_interval:
        aliases: ['tx-interval']
        type: int
        description: Frequency of LLDP PDU transmission from FortiSwitch
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure FortiSwitch LLDP settings.
      fortinet.fmgdevice.fmgd_switchcontroller_lldpsettings:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        switchcontroller_lldpsettings:
          # device_detection: <value in [disable, enable]>
          # fast_start_interval: <integer>
          # management_interface: <value in [internal, mgmt]>
          # tx_hold: <integer>
          # tx_interval: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-settings'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_lldpsettings': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'device-detection': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fast-start-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'management-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['internal', 'mgmt'], 'type': 'str'},
                'tx-hold': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'tx-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_lldpsettings'),
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
