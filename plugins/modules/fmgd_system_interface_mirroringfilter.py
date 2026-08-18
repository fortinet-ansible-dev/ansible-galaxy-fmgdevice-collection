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
module: fmgd_system_interface_mirroringfilter
short_description: Mirroring filter.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  interface:
    description: The parameter (interface) in requested url.
    type: str
    required: true
  system_interface_mirroringfilter:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      dbg_dump:
        aliases: ['dbg-dump']
        type: int
        description: Debug mirroring filter, driver dump data/mask pdq.
      filter_dport:
        aliases: ['filter-dport']
        type: int
        description: Destinatin port of mirroring filter.
      filter_dstip:
        aliases: ['filter-dstip']
        type: list
        elements: str
        description: Destinatin IP and mask of mirroring filter.
      filter_protocol:
        aliases: ['filter-protocol']
        type: int
        description: Protocol of mirroring filter.
      filter_sport:
        aliases: ['filter-sport']
        type: int
        description: Source port of mirroring filter.
      filter_srcip:
        aliases: ['filter-srcip']
        type: list
        elements: str
        description: Source IP and mask of mirroring filter.
      filter_dstip6:
        aliases: ['filter-dstip6']
        type: list
        elements: str
        description: Destinatin IP and mask of mirroring filter.
      filter_ethtype:
        aliases: ['filter-ethtype']
        type: int
        description: Ethtype of mirroring filter.
      filter_srcip6:
        aliases: ['filter-srcip6']
        type: list
        elements: str
        description: Source IP and mask of mirroring filter.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Mirroring filter.
      fortinet.fmgdevice.fmgd_system_interface_mirroringfilter:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        interface: <your own value>
        system_interface_mirroringfilter:
          # dbg_dump: <integer>
          # filter_dport: <integer>
          # filter_dstip: <list or string>
          # filter_protocol: <integer>
          # filter_sport: <integer>
          # filter_srcip: <list or string>
          # filter_dstip6: <list or string>
          # filter_ethtype: <integer>
          # filter_srcip6: <list or string>
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
        '/pm/config/device/{device}/global/system/interface/{interface}/mirroring-filter'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'system_interface_mirroringfilter': {
            'type': 'dict', 'v_range': [['7.4.3', '']],
            'options': {
                'dbg-dump': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'filter-dport': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'filter-dstip': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-protocol': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'filter-sport': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'filter-srcip': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'filter-dstip6': {'v_range': [['7.6.7', '7.6.7']], 'type': 'list', 'elements': 'str'},
                'filter-ethtype': {'v_range': [['7.6.7', '7.6.7']], 'type': 'int'},
                'filter-srcip6': {'v_range': [['7.6.7', '7.6.7']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_interface_mirroringfilter'),
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
