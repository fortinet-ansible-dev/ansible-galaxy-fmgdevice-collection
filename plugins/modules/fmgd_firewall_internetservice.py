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
module: fmgd_firewall_internetservice
short_description: Show Internet Service application.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  firewall_internetservice:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      database:
        type: str
        description: Database.
        choices: ['isdb', 'irdb']
      direction:
        type: str
        description: Direction.
        choices: ['src', 'dst', 'both']
      extra_ip_range_number:
        aliases: ['extra-ip-range-number']
        type: int
        description: Extra ip range number.
      extra_ip6_range_number:
        aliases: ['extra-ip6-range-number']
        type: int
        description: Extra ip6 range number.
      icon_id:
        aliases: ['icon-id']
        type: int
        description: Icon id.
      id:
        type: int
        description: Internet Service ID.
      ip_number:
        aliases: ['ip-number']
        type: int
        description: Ip number.
      ip_range_number:
        aliases: ['ip-range-number']
        type: int
        description: Ip range number.
      ip6_range_number:
        aliases: ['ip6-range-number']
        type: int
        description: Ip6 range number.
      name:
        type: str
        description: Name.
      obsolete:
        type: int
        description: Obsolete.
      singularity:
        type: int
        description: Singularity.
      reputation:
        type: int
        description: Reputation.
      sld_id:
        aliases: ['sld-id']
        type: int
        description: Sld id.
      entry:
        type: list
        elements: dict
        description: Entry.
        suboptions:
          id:
            type: int
            description: Entry ID.
          ip_number:
            aliases: ['ip-number']
            type: int
            description: Total number of IP addresses.
          ip_range_number:
            aliases: ['ip-range-number']
            type: int
            description: Total number of IP ranges.
          port:
            type: list
            elements: int
            description: Integer value for the TCP/IP port
          protocol:
            type: int
            description: Integer value for the protocol type as defined by IANA
      offset:
        type: int
        description: Offset.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Show Internet Service application.
      fortinet.fmgdevice.fmgd_firewall_internetservice:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        firewall_internetservice:
          # database: <value in [isdb, irdb]>
          # direction: <value in [src, dst, both]>
          # extra_ip_range_number: <integer>
          # extra_ip6_range_number: <integer>
          # icon_id: <integer>
          # id: <integer>
          # ip_number: <integer>
          # ip_range_number: <integer>
          # ip6_range_number: <integer>
          # name: <string>
          # obsolete: <integer>
          # singularity: <integer>
          # reputation: <integer>
          # sld_id: <integer>
          # entry:
          #   - id: <integer>
          #     ip_number: <integer>
          #     ip_range_number: <integer>
          #     port: <list or integer>
          #     protocol: <integer>
          # offset: <integer>
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
        '/pm/config/device/{device}/global/firewall/internet-service'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'firewall_internetservice': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'database': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['isdb', 'irdb'], 'type': 'str'},
                'direction': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['src', 'dst', 'both'], 'type': 'str'},
                'extra-ip-range-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'extra-ip6-range-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'icon-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ip-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ip-range-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ip6-range-number': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'obsolete': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'singularity': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'reputation': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                'sld-id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                'entry': {
                    'v_range': [['7.4.8', '7.4.11']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                        'ip-number': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                        'ip-range-number': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'},
                        'port': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'int'},
                        'protocol': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'offset': {'v_range': [['7.4.8', '7.4.11']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_internetservice'),
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
