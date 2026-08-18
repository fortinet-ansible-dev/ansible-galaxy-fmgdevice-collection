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
module: fmgd_router_multicast_interface_igmp
short_description: IGMP configuration options.
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
  interface:
    description: The parameter (interface) in requested url.
    type: str
    required: true
  router_multicast_interface_igmp:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      access_group:
        aliases: ['access-group']
        type: list
        elements: str
        description: Groups IGMP hosts are allowed to join.
      immediate_leave_group:
        aliases: ['immediate-leave-group']
        type: list
        elements: str
        description: Groups to drop membership for immediately after receiving IGMPv2 leave.
      last_member_query_count:
        aliases: ['last-member-query-count']
        type: int
        description: Number of group specific queries before removing group
      last_member_query_interval:
        aliases: ['last-member-query-interval']
        type: int
        description: Timeout between IGMPv2 leave and removing group
      query_interval:
        aliases: ['query-interval']
        type: int
        description: Interval between queries to IGMP hosts
      query_max_response_time:
        aliases: ['query-max-response-time']
        type: int
        description: Maximum time to wait for a IGMP query response
      query_timeout:
        aliases: ['query-timeout']
        type: int
        description: Timeout between queries before becoming querying unit for network
      router_alert_check:
        aliases: ['router-alert-check']
        type: str
        description: Enable/disable require IGMP packets contain router alert option.
        choices: ['disable', 'enable']
      version:
        type: str
        description: Maximum version of IGMP to support.
        choices: ['1', '2', '3']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: IGMP configuration options.
      fortinet.fmgdevice.fmgd_router_multicast_interface_igmp:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        interface: <your own value>
        router_multicast_interface_igmp:
          # access_group: <list or string>
          # immediate_leave_group: <list or string>
          # last_member_query_count: <integer>
          # last_member_query_interval: <integer>
          # query_interval: <integer>
          # query_max_response_time: <integer>
          # query_timeout: <integer>
          # router_alert_check: <value in [disable, enable]>
          # version: <value in [1, 2, 3]>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}/igmp'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'interface': {'required': True, 'type': 'str'},
        'router_multicast_interface_igmp': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'access-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'immediate-leave-group': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'last-member-query-count': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'last-member-query-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'query-interval': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'query-max-response-time': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'query-timeout': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'router-alert-check': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'version': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['1', '2', '3'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_multicast_interface_igmp'),
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
