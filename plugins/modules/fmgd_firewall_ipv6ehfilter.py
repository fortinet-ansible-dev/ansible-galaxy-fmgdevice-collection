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
module: fmgd_firewall_ipv6ehfilter
short_description: Configure IPv6 extension header filter.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  firewall_ipv6ehfilter:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      auth:
        type: str
        description: Enable/disable blocking packets with the Authentication header
        choices: ['disable', 'enable']
      dest_opt:
        aliases: ['dest-opt']
        type: str
        description: Enable/disable blocking packets with Destination Options headers
        choices: ['disable', 'enable']
      fragment:
        type: str
        description: Enable/disable blocking packets with the Fragment header
        choices: ['disable', 'enable']
      hdopt_type:
        aliases: ['hdopt-type']
        type: list
        elements: int
        description: Block specific Hop-by-Hop and/or Destination Option types
      hop_opt:
        aliases: ['hop-opt']
        type: str
        description: Enable/disable blocking packets with the Hop-by-Hop Options header
        choices: ['disable', 'enable']
      no_next:
        aliases: ['no-next']
        type: str
        description: Enable/disable blocking packets with the No Next header
        choices: ['disable', 'enable']
      routing:
        type: str
        description: Enable/disable blocking packets with Routing headers
        choices: ['disable', 'enable']
      routing_type:
        aliases: ['routing-type']
        type: list
        elements: int
        description: Block specific Routing header types
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv6 extension header filter.
      fortinet.fmgdevice.fmgd_firewall_ipv6ehfilter:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        firewall_ipv6ehfilter:
          # auth: <value in [disable, enable]>
          # dest_opt: <value in [disable, enable]>
          # fragment: <value in [disable, enable]>
          # hdopt_type: <list or integer>
          # hop_opt: <value in [disable, enable]>
          # no_next: <value in [disable, enable]>
          # routing: <value in [disable, enable]>
          # routing_type: <list or integer>
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
        '/pm/config/device/{device}/global/firewall/ipv6-eh-filter'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'firewall_ipv6ehfilter': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'auth': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dest-opt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fragment': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'hdopt-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'hop-opt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'no-next': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'routing': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'routing-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_ipv6ehfilter'),
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
