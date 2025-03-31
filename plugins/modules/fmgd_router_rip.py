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
module: fmgd_router_rip
short_description: Configure RIP.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    device:
        description: The parameter (device) in requested url.
        type: str
        required: true
    vdom:
        description: The parameter (vdom) in requested url.
        type: str
        required: true
    router_rip:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            default_information_originate:
                aliases: ['default-information-originate']
                type: str
                description: Enable/disable generation of default route.
                choices:
                    - 'disable'
                    - 'enable'
            default_metric:
                aliases: ['default-metric']
                type: int
                description: Default metric.
            distance:
                type: list
                elements: dict
                description: Distance.
                suboptions:
                    access_list:
                        aliases: ['access-list']
                        type: list
                        elements: str
                        description: Access list for route destination.
                    distance:
                        type: int
                        description: Distance
                    id:
                        type: int
                        description: Distance ID.
                    prefix:
                        type: list
                        elements: str
                        description: Distance prefix.
            distribute_list:
                aliases: ['distribute-list']
                type: list
                elements: dict
                description: Distribute list.
                suboptions:
                    direction:
                        type: str
                        description: Distribute list direction.
                        choices:
                            - 'out'
                            - 'in'
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
                        choices:
                            - 'disable'
                            - 'enable'
            garbage_timer:
                aliases: ['garbage-timer']
                type: int
                description: Garbage timer in seconds.
            interface:
                type: list
                elements: dict
                description: Interface.
                suboptions:
                    auth_keychain:
                        aliases: ['auth-keychain']
                        type: list
                        elements: str
                        description: Authentication key-chain name.
                    auth_mode:
                        aliases: ['auth-mode']
                        type: str
                        description: Authentication mode.
                        choices:
                            - 'none'
                            - 'md5'
                            - 'text'
                    auth_string:
                        aliases: ['auth-string']
                        type: list
                        elements: str
                        description: Authentication string/password.
                    flags:
                        type: int
                        description: Flags.
                    name:
                        type: str
                        description: Interface name.
                    receive_version:
                        aliases: ['receive-version']
                        type: list
                        elements: str
                        description: Receive version.
                        choices:
                            - '1'
                            - '2'
                    send_version:
                        aliases: ['send-version']
                        type: list
                        elements: str
                        description: Send version.
                        choices:
                            - '1'
                            - '2'
                    send_version2_broadcast:
                        aliases: ['send-version2-broadcast']
                        type: str
                        description: Enable/disable broadcast version 1 compatible packets.
                        choices:
                            - 'disable'
                            - 'enable'
                    split_horizon:
                        aliases: ['split-horizon']
                        type: str
                        description: Enable/disable split horizon.
                        choices:
                            - 'poisoned'
                            - 'regular'
                    split_horizon_status:
                        aliases: ['split-horizon-status']
                        type: str
                        description: Enable/disable split horizon.
                        choices:
                            - 'disable'
                            - 'enable'
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
                    ip:
                        type: str
                        description: IP address.
            network:
                type: list
                elements: dict
                description: Network.
                suboptions:
                    id:
                        type: int
                        description: Network entry ID.
                    prefix:
                        type: list
                        elements: str
                        description: Network prefix.
            offset_list:
                aliases: ['offset-list']
                type: list
                elements: dict
                description: Offset list.
                suboptions:
                    access_list:
                        aliases: ['access-list']
                        type: list
                        elements: str
                        description: Access list name.
                    direction:
                        type: str
                        description: Offset list direction.
                        choices:
                            - 'out'
                            - 'in'
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
                        choices:
                            - 'disable'
                            - 'enable'
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
                        choices:
                            - 'disable'
                            - 'enable'
            timeout_timer:
                aliases: ['timeout-timer']
                type: int
                description: Timeout timer in seconds.
            update_timer:
                aliases: ['update-timer']
                type: int
                description: Update timer in seconds.
            version:
                type: str
                description: RIP version.
                choices:
                    - '1'
                    - '2'
            recv_buffer_size:
                aliases: ['recv-buffer-size']
                type: int
                description: Receiving buffer size.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure RIP.
      fortinet.fmgdevice.fmgd_router_rip:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        router_rip:
          # default_information_originate: <value in [disable, enable]>
          # default_metric: <integer>
          # distance:
          #   - access_list: <list or string>
          #     distance: <integer>
          #     id: <integer>
          #     prefix: <list or string>
          # distribute_list:
          #   - direction: <value in [out, in]>
          #     id: <integer>
          #     interface: <list or string>
          #     listname: <list or string>
          #     status: <value in [disable, enable]>
          # garbage_timer: <integer>
          # interface:
          #   - auth_keychain: <list or string>
          #     auth_mode: <value in [none, md5, text]>
          #     auth_string: <list or string>
          #     flags: <integer>
          #     name: <string>
          #     receive_version:
          #       - "1"
          #       - "2"
          #     send_version:
          #       - "1"
          #       - "2"
          #     send_version2_broadcast: <value in [disable, enable]>
          #     split_horizon: <value in [poisoned, regular]>
          #     split_horizon_status: <value in [disable, enable]>
          # max_out_metric: <integer>
          # neighbor:
          #   - id: <integer>
          #     ip: <string>
          # network:
          #   - id: <integer>
          #     prefix: <list or string>
          # offset_list:
          #   - access_list: <list or string>
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
          # version: <value in [1, 2]>
          # recv_buffer_size: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/rip'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_rip': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'default-information-originate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'default-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'distance': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'distance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'distribute-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['out', 'in'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'listname': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'garbage-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'auth-keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'auth-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'md5', 'text'], 'type': 'str'},
                        'auth-string': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'flags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'receive-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['1', '2'], 'elements': 'str'},
                        'send-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['1', '2'], 'elements': 'str'},
                        'send-version2-broadcast': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'split-horizon': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['poisoned', 'regular'], 'type': 'str'},
                        'split-horizon-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'max-out-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'neighbor': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'network': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'offset-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['out', 'in'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'offset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'passive-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'redistribute': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'routemap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'timeout-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'update-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['1', '2'], 'type': 'str'},
                'recv-buffer-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_rip'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
