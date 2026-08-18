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
module: fmgd_system_sdwan_duplication
short_description: Create SD-WAN duplication rule.
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
  system_sdwan_duplication:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      dstaddr:
        type: list
        elements: str
        description: Destination address or address group names.
      dstaddr6:
        type: list
        elements: str
        description: Destination address6 or address6 group names.
      dstintf:
        type: list
        elements: str
        description: Outgoing
      id:
        type: int
        description: Duplication rule ID
        required: true
      packet_de_duplication:
        aliases: ['packet-de-duplication']
        type: str
        description: Enable/disable discarding of packets that have been duplicated.
        choices: ['disable', 'enable']
      packet_duplication:
        aliases: ['packet-duplication']
        type: str
        description: Configure packet duplication method.
        choices: ['disable', 'force', 'on-demand']
      service:
        type: list
        elements: str
        description: Service and service group name.
      service_id:
        aliases: ['service-id']
        type: list
        elements: str
        description: SD-WAN service rule ID list.
      sla_match_service:
        aliases: ['sla-match-service']
        type: str
        description: Enable/disable packet duplication matching health-check SLAs in service rule.
        choices: ['disable', 'enable']
      srcaddr:
        type: list
        elements: str
        description: Source address or address group names.
      srcaddr6:
        type: list
        elements: str
        description: Source address6 or address6 group names.
      srcintf:
        type: list
        elements: str
        description: Incoming
      members:
        type: list
        elements: str
        description: Member sequence number list.
      tos:
        type: str
        description: Type of service bit pattern.
      tos_mask:
        aliases: ['tos-mask']
        type: str
        description: Type of service evaluated bits.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Create SD-WAN duplication rule.
      fortinet.fmgdevice.fmgd_system_sdwan_duplication:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_sdwan_duplication:
          id: 0 # Required variable, integer
          # dstaddr: <list or string>
          # dstaddr6: <list or string>
          # dstintf: <list or string>
          # packet_de_duplication: <value in [disable, enable]>
          # packet_duplication: <value in [disable, force, on-demand]>
          # service: <list or string>
          # service_id: <list or string>
          # sla_match_service: <value in [disable, enable]>
          # srcaddr: <list or string>
          # srcaddr6: <list or string>
          # srcintf: <list or string>
          # members: <list or string>
          # tos: <string>
          # tos_mask: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/duplication'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_sdwan_duplication': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'dstaddr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dstintf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'packet-de-duplication': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'packet-duplication': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'force', 'on-demand'], 'type': 'str'},
                'service': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'service-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'sla-match-service': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'srcaddr6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'srcintf': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'members': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'tos': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'tos-mask': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdwan_duplication'),
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
