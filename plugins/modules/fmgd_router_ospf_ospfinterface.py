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
module: fmgd_router_ospf_ospfinterface
short_description: OSPF interface configuration.
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
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    router_ospf_ospfinterface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authentication:
                type: str
                description: Authentication type.
                choices:
                    - 'none'
                    - 'text'
                    - 'md5'
                    - 'message-digest'
            authentication_key:
                aliases: ['authentication-key']
                type: list
                elements: str
                description: Authentication key.
            bfd:
                type: str
                description: Bidirectional Forwarding Detection
                choices:
                    - 'global'
                    - 'enable'
                    - 'disable'
            comments:
                type: str
                description: Comment.
            cost:
                type: int
                description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
            database_filter_out:
                aliases: ['database-filter-out']
                type: str
                description: Enable/disable control of flooding out LSAs.
                choices:
                    - 'disable'
                    - 'enable'
            dead_interval:
                aliases: ['dead-interval']
                type: int
                description: Dead interval.
            hello_interval:
                aliases: ['hello-interval']
                type: int
                description: Hello interval.
            hello_multiplier:
                aliases: ['hello-multiplier']
                type: int
                description: Number of hello packets within dead interval.
            interface:
                type: list
                elements: str
                description: Configuration interface name.
            ip:
                type: str
                description: IP address.
            keychain:
                type: list
                elements: str
                description: Message-digest key-chain name.
            md5_keys:
                aliases: ['md5-keys']
                type: list
                elements: dict
                description: Md5 keys.
                suboptions:
                    id:
                        type: int
                        description: Key ID
                    key_string:
                        aliases: ['key-string']
                        type: list
                        elements: str
                        description: Password for the key.
            mtu:
                type: int
                description: MTU for database description packets.
            mtu_ignore:
                aliases: ['mtu-ignore']
                type: str
                description: Enable/disable ignore MTU.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Interface entry name.
                required: true
            network_type:
                aliases: ['network-type']
                type: str
                description: Network type.
                choices:
                    - 'broadcast'
                    - 'non-broadcast'
                    - 'point-to-point'
                    - 'point-to-multipoint'
                    - 'point-to-multipoint-non-broadcast'
            prefix_length:
                aliases: ['prefix-length']
                type: int
                description: Prefix length.
            priority:
                type: int
                description: Priority.
            resync_timeout:
                aliases: ['resync-timeout']
                type: int
                description: Graceful restart neighbor resynchronization timeout.
            retransmit_interval:
                aliases: ['retransmit-interval']
                type: int
                description: Retransmit interval.
            status:
                type: str
                description: Enable/disable status.
                choices:
                    - 'disable'
                    - 'enable'
            transmit_delay:
                aliases: ['transmit-delay']
                type: int
                description: Transmit delay.
            md5_keychain:
                aliases: ['md5-keychain']
                type: list
                elements: str
                description: Authentication MD5 key-chain name.
            linkdown_fast_failover:
                aliases: ['linkdown-fast-failover']
                type: str
                description: Enable/disable fast link failover.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: OSPF interface configuration.
      fortinet.fmgdevice.fmgd_router_ospf_ospfinterface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_ospf_ospfinterface:
          name: "your value" # Required variable, string
          # authentication: <value in [none, text, md5, ...]>
          # authentication_key: <list or string>
          # bfd: <value in [global, enable, disable]>
          # comments: <string>
          # cost: <integer>
          # database_filter_out: <value in [disable, enable]>
          # dead_interval: <integer>
          # hello_interval: <integer>
          # hello_multiplier: <integer>
          # interface: <list or string>
          # ip: <string>
          # keychain: <list or string>
          # md5_keys:
          #   - id: <integer>
          #     key_string: <list or string>
          # mtu: <integer>
          # mtu_ignore: <value in [disable, enable]>
          # network_type: <value in [broadcast, non-broadcast, point-to-point, ...]>
          # prefix_length: <integer>
          # priority: <integer>
          # resync_timeout: <integer>
          # retransmit_interval: <integer>
          # status: <value in [disable, enable]>
          # transmit_delay: <integer>
          # md5_keychain: <list or string>
          # linkdown_fast_failover: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ospf_ospfinterface': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'text', 'md5', 'message-digest'], 'type': 'str'},
                'authentication-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['global', 'enable', 'disable'], 'type': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'database-filter-out': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-multiplier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'md5-keys': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'key-string': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mtu-ignore': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'network-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['broadcast', 'non-broadcast', 'point-to-point', 'point-to-multipoint', 'point-to-multipoint-non-broadcast'],
                    'type': 'str'
                },
                'prefix-length': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'resync-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'md5-keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'linkdown-fast-failover': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf_ospfinterface'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgd.validate_parameters(params_validation_blob)
    fmgd.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
