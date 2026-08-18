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
module: fmgd_router_multicast6flow_flows
short_description: IPv6 multicast-flow entries.
version_added: "1.2.0"
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
  multicast6-flow:
    description: Deprecated, please use "multicast6_flow"
    type: str
  multicast6_flow:
    description: The parameter (multicast6-flow) in requested url.
    type: str
  router_multicast6flow_flows:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      group_addr:
        aliases: ['group-addr']
        type: str
        description: Multicast group IP address.
      id:
        type: int
        description: Flow ID.
        required: true
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IPv6 multicast-flow entries.
      fortinet.fmgdevice.fmgd_router_multicast6flow_flows:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        multicast6_flow: <your own value>
        state: present # <value in [present, absent]>
        router_multicast6flow_flows:
          id: 0 # Required variable, integer
          # group_addr: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/multicast6-flow/{multicast6-flow}/flows'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'multicast6-flow': {'type': 'str', 'api_name': 'multicast6_flow'},
        'multicast6_flow': {'type': 'str'},
        'router_multicast6flow_flows': {
            'type': 'dict', 'v_range': [['8.0.0', '']],
            'options': {'group-addr': {'v_range': [['8.0.0', '']], 'type': 'str'}, 'id': {'v_range': [['8.0.0', '']], 'required': True, 'type': 'int'}}
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast6flow_flows'),
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
