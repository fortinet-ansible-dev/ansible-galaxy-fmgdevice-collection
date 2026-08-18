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
module: fmgd_switchcontroller_lldpprofile_mednetworkpolicy
short_description: Configuration method to edit Media Endpoint Discovery
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
  lldp-profile:
    description: Deprecated, please use "lldp_profile"
    type: str
  lldp_profile:
    description: The parameter (lldp-profile) in requested url.
    type: str
  switchcontroller_lldpprofile_mednetworkpolicy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      assign_vlan:
        aliases: ['assign-vlan']
        type: str
        description: Enable/disable VLAN assignment when this profile is applied on managed FortiSwitch port.
        choices: ['disable', 'enable']
      dscp:
        type: int
        description: Advertised Differentiated Services Code Point
      name:
        type: str
        description: Policy type name.
        required: true
      priority:
        type: int
        description: Advertised Layer 2 priority
      status:
        type: str
        description: Enable or disable this TLV.
        choices: ['disable', 'enable']
      vlan:
        type: int
        description: ID of VLAN to advertise, if configured on port
      vlan_intf:
        aliases: ['vlan-intf']
        type: list
        elements: str
        description: VLAN interface to advertise; if configured on port.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configuration method to edit Media Endpoint Discovery
      fortinet.fmgdevice.fmgd_switchcontroller_lldpprofile_mednetworkpolicy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        lldp_profile: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_lldpprofile_mednetworkpolicy:
          name: "your value" # Required variable, string
          # assign_vlan: <value in [disable, enable]>
          # dscp: <integer>
          # priority: <integer>
          # status: <value in [disable, enable]>
          # vlan: <integer>
          # vlan_intf: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-network-policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'lldp-profile': {'type': 'str', 'api_name': 'lldp_profile'},
        'lldp_profile': {'type': 'str'},
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'assign-vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'vlan-intf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_lldpprofile_mednetworkpolicy'),
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
