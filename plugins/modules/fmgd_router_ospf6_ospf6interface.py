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
module: fmgd_router_ospf6_ospf6interface
short_description: OSPF6 interface configuration.
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
    router_ospf6_ospf6interface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            area_id:
                aliases: ['area-id']
                type: str
                description: A.
            authentication:
                type: str
                description: Authentication mode.
                choices:
                    - 'none'
                    - 'ah'
                    - 'esp'
                    - 'area'
            bfd:
                type: str
                description: Enable/disable Bidirectional Forwarding Detection
                choices:
                    - 'global'
                    - 'enable'
                    - 'disable'
            cost:
                type: int
                description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
            dead_interval:
                aliases: ['dead-interval']
                type: int
                description: Dead interval.
            hello_interval:
                aliases: ['hello-interval']
                type: int
                description: Hello interval.
            interface:
                type: list
                elements: str
                description: Configuration interface name.
            ipsec_auth_alg:
                aliases: ['ipsec-auth-alg']
                type: str
                description: Authentication algorithm.
                choices:
                    - 'md5'
                    - 'sha1'
                    - 'sha256'
                    - 'sha384'
                    - 'sha512'
            ipsec_enc_alg:
                aliases: ['ipsec-enc-alg']
                type: str
                description: Encryption algorithm.
                choices:
                    - 'null'
                    - 'des'
                    - '3des'
                    - 'aes128'
                    - 'aes192'
                    - 'aes256'
            ipsec_keys:
                aliases: ['ipsec-keys']
                type: list
                elements: dict
                description: Ipsec keys.
                suboptions:
                    auth_key:
                        aliases: ['auth-key']
                        type: list
                        elements: str
                        description: Authentication key.
                    enc_key:
                        aliases: ['enc-key']
                        type: list
                        elements: str
                        description: Encryption key.
                    spi:
                        type: int
                        description: Security Parameters Index.
            key_rollover_interval:
                aliases: ['key-rollover-interval']
                type: int
                description: Key roll-over interval.
            mtu:
                type: int
                description: MTU for OSPFv3 packets.
            mtu_ignore:
                aliases: ['mtu-ignore']
                type: str
                description: Enable/disable ignoring MTU field in DBD packets.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Interface entry name.
                required: true
            neighbor:
                type: list
                elements: dict
                description: Neighbor.
                suboptions:
                    cost:
                        type: int
                        description: Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                    ip6:
                        type: str
                        description: IPv6 link local address of the neighbor.
                    poll_interval:
                        aliases: ['poll-interval']
                        type: int
                        description: Poll interval time in seconds.
                    priority:
                        type: int
                        description: Priority.
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
            priority:
                type: int
                description: Priority.
            retransmit_interval:
                aliases: ['retransmit-interval']
                type: int
                description: Retransmit interval.
            status:
                type: str
                description: Enable/disable OSPF6 routing on this interface.
                choices:
                    - 'disable'
                    - 'enable'
            transmit_delay:
                aliases: ['transmit-delay']
                type: int
                description: Transmit delay.
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
    - name: OSPF6 interface configuration.
      fortinet.fmgdevice.fmgd_router_ospf6_ospf6interface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_ospf6_ospf6interface:
          name: "your value" # Required variable, string
          # area_id: <string>
          # authentication: <value in [none, ah, esp, ...]>
          # bfd: <value in [global, enable, disable]>
          # cost: <integer>
          # dead_interval: <integer>
          # hello_interval: <integer>
          # interface: <list or string>
          # ipsec_auth_alg: <value in [md5, sha1, sha256, ...]>
          # ipsec_enc_alg: <value in [null, des, 3des, ...]>
          # ipsec_keys:
          #   - auth_key: <list or string>
          #     enc_key: <list or string>
          #     spi: <integer>
          # key_rollover_interval: <integer>
          # mtu: <integer>
          # mtu_ignore: <value in [disable, enable]>
          # neighbor:
          #   - cost: <integer>
          #     ip6: <string>
          #     poll_interval: <integer>
          #     priority: <integer>
          # network_type: <value in [broadcast, non-broadcast, point-to-point, ...]>
          # priority: <integer>
          # retransmit_interval: <integer>
          # status: <value in [disable, enable]>
          # transmit_delay: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ospf6_ospf6interface': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'area-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'ah', 'esp', 'area'], 'type': 'str'},
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['global', 'enable', 'disable'], 'type': 'str'},
                'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ipsec-auth-alg': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                    'type': 'str'
                },
                'ipsec-enc-alg': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256'],
                    'type': 'str'
                },
                'ipsec-keys': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'no_log': True,
                    'type': 'list',
                    'options': {
                        'auth-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'enc-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'key-rollover-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'mtu': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mtu-ignore': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'neighbor': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'ip6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'poll-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'network-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['broadcast', 'non-broadcast', 'point-to-point', 'point-to-multipoint', 'point-to-multipoint-non-broadcast'],
                    'type': 'str'
                },
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf6_ospf6interface'),
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
