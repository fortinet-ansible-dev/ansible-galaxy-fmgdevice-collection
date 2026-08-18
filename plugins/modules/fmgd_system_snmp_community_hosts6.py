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
module: fmgd_system_snmp_community_hosts6
short_description: Configure IPv6 SNMP managers.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  community:
    description: The parameter (community) in requested url.
    type: str
    required: true
  system_snmp_community_hosts6:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      ha_direct:
        aliases: ['ha-direct']
        type: str
        description: Enable/disable direct management of HA cluster members.
        choices: ['disable', 'enable']
      host_type:
        aliases: ['host-type']
        type: str
        description: Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.
        choices: ['any', 'query', 'trap']
      id:
        type: int
        description: Host6 entry ID.
        required: true
      ipv6:
        type: str
        description: SNMP manager IPv6 address prefix.
      source_ipv6:
        aliases: ['source-ipv6']
        type: str
        description: Source IPv6 address for SNMP traps.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      vrf_select:
        aliases: ['vrf-select']
        type: int
        description: VRF ID used for connection to server.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 SNMP managers.
      fortinet.fmgdevice.fmgd_system_snmp_community_hosts6:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        community: <your own value>
        state: present # <value in [present, absent]>
        system_snmp_community_hosts6:
          id: 0 # Required variable, integer
          # ha_direct: <value in [disable, enable]>
          # host_type: <value in [any, query, trap]>
          # ipv6: <string>
          # source_ipv6: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts6'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'community': {'required': True, 'type': 'str'},
        'system_snmp_community_hosts6': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'ha-direct': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'host-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['any', 'query', 'trap'], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'ipv6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'source-ipv6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'interface': {'v_range': [['7.6.0', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.6.0', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_snmp_community_hosts6'),
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
