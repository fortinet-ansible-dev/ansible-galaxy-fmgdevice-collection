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
module: fmgd_router_ripng
short_description: Configure RIPng.
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
  router_ripng:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      aggregate_address:
        aliases: ['aggregate-address']
        type: list
        elements: dict
        description: Aggregate address.
        suboptions:
          id:
            type: int
            description: Aggregate address entry ID.
          prefix6:
            type: str
            description: Aggregate address prefix.
      default_information_originate:
        aliases: ['default-information-originate']
        type: str
        description: Enable/disable generation of default route.
        choices: ['disable', 'enable']
      default_metric:
        aliases: ['default-metric']
        type: int
        description: Default metric.
      distance:
        type: list
        elements: dict
        description: Distance.
        suboptions:
          access_list6:
            aliases: ['access-list6']
            type: list
            elements: str
            description: Access list for route destination.
          distance:
            type: int
            description: Distance
          id:
            type: int
            description: Distance ID.
          prefix6:
            type: str
            description: Distance prefix6.
      distribute_list:
        aliases: ['distribute-list']
        type: list
        elements: dict
        description: Distribute list.
        suboptions:
          direction:
            type: str
            description: Distribute list direction.
            choices: ['out', 'in']
          id:
            type: int
            description: Distribute list ID.
          interface:
            type: list
            elements: str
            description: Distribute list interface name.
          listname:
            type: list
            elements: str
            description: Distribute access/prefix list name.
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
      garbage_timer:
        aliases: ['garbage-timer']
        type: int
        description: Garbage timer.
      interface:
        type: list
        elements: dict
        description: Interface.
        suboptions:
          flags:
            type: int
            description: Flags.
          name:
            type: list
            elements: str
            description: Interface name.
          split_horizon:
            aliases: ['split-horizon']
            type: str
            description: Enable/disable split horizon.
            choices: ['poisoned', 'regular']
          split_horizon_status:
            aliases: ['split-horizon-status']
            type: str
            description: Enable/disable split horizon.
            choices: ['disable', 'enable']
      max_out_metric:
        aliases: ['max-out-metric']
        type: int
        description: Maximum metric allowed to output
      neighbor:
        type: list
        elements: dict
        description: Neighbor.
        suboptions:
          id:
            type: int
            description: Neighbor entry ID.
          interface:
            type: list
            elements: str
            description: Interface name.
          ip6:
            type: str
            description: IPv6 link-local address.
      network:
        type: list
        elements: dict
        description: Network.
        suboptions:
          id:
            type: int
            description: Network entry ID.
          prefix:
            type: str
            description: Network IPv6 link-local prefix.
      offset_list:
        aliases: ['offset-list']
        type: list
        elements: dict
        description: Offset list.
        suboptions:
          access_list6:
            aliases: ['access-list6']
            type: list
            elements: str
            description: IPv6 access list name.
          direction:
            type: str
            description: Offset list direction.
            choices: ['out', 'in']
          id:
            type: int
            description: Offset-list ID.
          interface:
            type: list
            elements: str
            description: Interface name.
          offset:
            type: int
            description: Offset.
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
      passive_interface:
        aliases: ['passive-interface']
        type: list
        elements: str
        description: Passive interface configuration.
      redistribute:
        type: dict
        description: Redistribute.
        suboptions:
          metric:
            type: int
            description: Redistribute metric setting.
          name:
            type: str
            description: Redistribute name.
          routemap:
            type: list
            elements: str
            description: Route map name.
          status:
            type: str
            description: Status.
            choices: ['disable', 'enable']
      timeout_timer:
        aliases: ['timeout-timer']
        type: int
        description: Timeout timer.
      update_timer:
        aliases: ['update-timer']
        type: int
        description: Update timer.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure RIPng.
      fortinet.fmgdevice.fmgd_router_ripng:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        router_ripng:
          # aggregate_address:
          #   - id: <integer>
          #     prefix6: <string>
          # default_information_originate: <value in [disable, enable]>
          # default_metric: <integer>
          # distance:
          #   - access_list6: <list or string>
          #     distance: <integer>
          #     id: <integer>
          #     prefix6: <string>
          # distribute_list:
          #   - direction: <value in [out, in]>
          #     id: <integer>
          #     interface: <list or string>
          #     listname: <list or string>
          #     status: <value in [disable, enable]>
          # garbage_timer: <integer>
          # interface:
          #   - flags: <integer>
          #     name: <list or string>
          #     split_horizon: <value in [poisoned, regular]>
          #     split_horizon_status: <value in [disable, enable]>
          # max_out_metric: <integer>
          # neighbor:
          #   - id: <integer>
          #     interface: <list or string>
          #     ip6: <string>
          # network:
          #   - id: <integer>
          #     prefix: <string>
          # offset_list:
          #   - access_list6: <list or string>
          #     direction: <value in [out, in]>
          #     id: <integer>
          #     interface: <list or string>
          #     offset: <integer>
          #     status: <value in [disable, enable]>
          # passive_interface: <list or string>
          # redistribute:
          #   metric: <integer>
          #   name: <string>
          #   routemap: <list or string>
          #   status: <value in [disable, enable]>
          # timeout_timer: <integer>
          # update_timer: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ripng'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ripng': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'aggregate-address': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'prefix6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'default-information-originate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-metric': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'distance': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-list6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'distance': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'prefix6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'distribute-list': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['out', 'in'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'listname': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'garbage-timer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'interface': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'flags': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'split-horizon': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['poisoned', 'regular'], 'type': 'str'},
                        'split-horizon-status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'max-out-metric': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'neighbor': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ip6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'network': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'offset-list': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-list6': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'direction': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['out', 'in'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'offset': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'passive-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'redistribute': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'metric': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'routemap': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'timeout-timer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'update-timer': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ripng'),
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
