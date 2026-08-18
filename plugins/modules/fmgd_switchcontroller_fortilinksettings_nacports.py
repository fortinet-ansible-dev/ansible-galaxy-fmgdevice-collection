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
module: fmgd_switchcontroller_fortilinksettings_nacports
short_description: NAC specific configuration.
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
  fortilink-settings:
    description: Deprecated, please use "fortilink_settings"
    type: str
  fortilink_settings:
    description: The parameter (fortilink-settings) in requested url.
    type: str
  switchcontroller_fortilinksettings_nacports:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      lan_segment:
        aliases: ['lan-segment']
        type: str
        description: Enable/disable LAN segment feature on the FortiLink interface.
        choices: ['disabled', 'enabled']
      member_change:
        aliases: ['member-change']
        type: int
        description: Member change.
      nac_lan_interface:
        aliases: ['nac-lan-interface']
        type: list
        elements: str
        description: Configure NAC LAN interface.
      nac_segment_vlans:
        aliases: ['nac-segment-vlans']
        type: list
        elements: str
        description: Configure NAC segment VLANs.
      onboarding_vlan:
        aliases: ['onboarding-vlan']
        type: list
        elements: str
        description: Default NAC Onboarding VLAN when NAC devices are discovered.
      parent_key:
        aliases: ['parent-key']
        type: str
        description: Parent key.
      bounce_nac_port:
        aliases: ['bounce-nac-port']
        type: str
        description: Enable/disable bouncing
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: NAC specific configuration.
      fortinet.fmgdevice.fmgd_switchcontroller_fortilinksettings_nacports:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        fortilink_settings: <your own value>
        switchcontroller_fortilinksettings_nacports:
          # lan_segment: <value in [disabled, enabled]>
          # member_change: <integer>
          # nac_lan_interface: <list or string>
          # nac_segment_vlans: <list or string>
          # onboarding_vlan: <list or string>
          # parent_key: <string>
          # bounce_nac_port: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/fortilink-settings/{fortilink-settings}/nac-ports'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'fortilink-settings': {'type': 'str', 'api_name': 'fortilink_settings'},
        'fortilink_settings': {'type': 'str'},
        'switchcontroller_fortilinksettings_nacports': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'lan-segment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                'member-change': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'nac-lan-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'nac-segment-vlans': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'onboarding-vlan': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'parent-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'bounce-nac-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_fortilinksettings_nacports'),
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
