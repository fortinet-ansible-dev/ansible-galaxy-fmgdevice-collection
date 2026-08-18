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
module: fmgd_switchcontroller_dynamicportpolicy_policy
short_description: Port policies with matching criteria and actions.
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
  dynamic-port-policy:
    description: Deprecated, please use "dynamic_port_policy"
    type: str
  dynamic_port_policy:
    description: The parameter (dynamic-port-policy) in requested url.
    type: str
  switchcontroller_dynamicportpolicy_policy:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      802_1x:
        aliases: ['802-1x']
        type: list
        elements: str
        description: '802.'
      bounce_port_link:
        aliases: ['bounce-port-link']
        type: str
        description: Enable/disable bouncing
        choices: ['disable', 'enable']
      category:
        type: str
        description: Category of Dynamic port policy.
        choices: ['device', 'interface-tag']
      description:
        type: str
        description: Description for the policy.
      family:
        type: str
        description: Match policy based on family.
      host:
        type: str
        description: Match policy based on host.
      hw_vendor:
        aliases: ['hw-vendor']
        type: str
        description: Match policy based on hardware vendor.
      interface_tags:
        aliases: ['interface-tags']
        type: list
        elements: str
        description: Match policy based on the FortiSwitch interface object tags.
      lldp_profile:
        aliases: ['lldp-profile']
        type: list
        elements: str
        description: LLDP profile to be applied when using this policy.
      mac:
        type: str
        description: Match policy based on MAC address.
      match_period:
        aliases: ['match-period']
        type: int
        description: Number of days the matched devices will be retained
      match_type:
        aliases: ['match-type']
        type: str
        description: Match and retain the devices based on the type.
        choices: ['dynamic', 'override']
      name:
        type: str
        description: Policy name.
        required: true
      qos_policy:
        aliases: ['qos-policy']
        type: list
        elements: str
        description: QoS policy to be applied when using this policy.
      status:
        type: str
        description: Enable/disable policy.
        choices: ['disable', 'enable']
      type:
        type: str
        description: Match policy based on type.
      vlan_policy:
        aliases: ['vlan-policy']
        type: list
        elements: str
        description: VLAN policy to be applied when using this policy.
      bounce_port_duration:
        aliases: ['bounce-port-duration']
        type: int
        description: Bounce duration in seconds of a switch port where this policy is applied.
      poe_reset:
        aliases: ['poe-reset']
        type: str
        description: Enable/disable POE reset of a switch port where this policy is applied.
        choices: ['disable', 'enable']
      match_remove:
        aliases: ['match-remove']
        type: str
        description: Options to remove the matched override devices.
        choices: ['link-down', 'default']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Port policies with matching criteria and actions.
      fortinet.fmgdevice.fmgd_switchcontroller_dynamicportpolicy_policy:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        dynamic_port_policy: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_dynamicportpolicy_policy:
          name: "your value" # Required variable, string
          # 802_1x: <list or string>
          # bounce_port_link: <value in [disable, enable]>
          # category: <value in [device, interface-tag]>
          # description: <string>
          # family: <string>
          # host: <string>
          # hw_vendor: <string>
          # interface_tags: <list or string>
          # lldp_profile: <list or string>
          # mac: <string>
          # match_period: <integer>
          # match_type: <value in [dynamic, override]>
          # qos_policy: <list or string>
          # status: <value in [disable, enable]>
          # type: <string>
          # vlan_policy: <list or string>
          # bounce_port_duration: <integer>
          # poe_reset: <value in [disable, enable]>
          # match_remove: <value in [link-down, default]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'dynamic-port-policy': {'type': 'str', 'api_name': 'dynamic_port_policy'},
        'dynamic_port_policy': {'type': 'str'},
        'switchcontroller_dynamicportpolicy_policy': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                '802-1x': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'bounce-port-link': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'category': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['device', 'interface-tag'], 'type': 'str'},
                'description': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'family': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'host': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'hw-vendor': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface-tags': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'lldp-profile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'mac': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'match-period': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'match-type': {'v_range': [['7.4.3', '']], 'choices': ['dynamic', 'override'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'qos-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'vlan-policy': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'bounce-port-duration': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'poe-reset': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'match-remove': {'v_range': [['7.6.3', '']], 'choices': ['link-down', 'default'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_dynamicportpolicy_policy'),
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
