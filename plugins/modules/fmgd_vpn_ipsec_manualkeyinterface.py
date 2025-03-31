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
module: fmgd_vpn_ipsec_manualkeyinterface
short_description: Configure IPsec manual keys.
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
    vpn_ipsec_manualkeyinterface:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            addr_type:
                aliases: ['addr-type']
                type: str
                description: IP version to use for IP packets.
                choices:
                    - '4'
                    - '6'
            auth_alg:
                aliases: ['auth-alg']
                type: str
                description: Authentication algorithm.
                choices:
                    - 'null'
                    - 'md5'
                    - 'sha1'
                    - 'sha256'
                    - 'sha384'
                    - 'sha512'
            auth_key:
                aliases: ['auth-key']
                type: list
                elements: str
                description: Hexadecimal authentication key in 16-digit
            enc_alg:
                aliases: ['enc-alg']
                type: str
                description: Encryption algorithm.
                choices:
                    - 'null'
                    - 'des'
                    - '3des'
                    - 'aes128'
                    - 'aes192'
                    - 'aes256'
                    - 'aria128'
                    - 'aria192'
                    - 'aria256'
                    - 'seed'
            enc_key:
                aliases: ['enc-key']
                type: list
                elements: str
                description: Hexadecimal encryption key in 16-digit
            interface:
                type: list
                elements: str
                description: Name of the physical, aggregate, or VLAN interface.
            ip_version:
                aliases: ['ip-version']
                type: str
                description: IP version to use for VPN interface.
                choices:
                    - '4'
                    - '6'
            local_gw:
                aliases: ['local-gw']
                type: str
                description: IPv4 address of the local gateways external interface.
            local_gw6:
                aliases: ['local-gw6']
                type: str
                description: Local IPv6 address of VPN gateway.
            local_spi:
                aliases: ['local-spi']
                type: str
                description: Local SPI, a hexadecimal 8-digit
            name:
                type: str
                description: IPsec tunnel name.
                required: true
            npu_offload:
                aliases: ['npu-offload']
                type: str
                description: Enable/disable offloading IPsec VPN manual key sessions to NPUs.
                choices:
                    - 'disable'
                    - 'enable'
            remote_gw:
                aliases: ['remote-gw']
                type: str
                description: IPv4 address of the remote gateways external interface.
            remote_gw6:
                aliases: ['remote-gw6']
                type: str
                description: Remote IPv6 address of VPN gateway.
            remote_spi:
                aliases: ['remote-spi']
                type: str
                description: Remote SPI, a hexadecimal 8-digit
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
    - name: Configure IPsec manual keys.
      fortinet.fmgdevice.fmgd_vpn_ipsec_manualkeyinterface:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_ipsec_manualkeyinterface:
          name: "your value" # Required variable, string
          # addr_type: <value in [4, 6]>
          # auth_alg: <value in [null, md5, sha1, ...]>
          # auth_key: <list or string>
          # enc_alg: <value in [null, des, 3des, ...]>
          # enc_key: <list or string>
          # interface: <list or string>
          # ip_version: <value in [4, 6]>
          # local_gw: <string>
          # local_gw6: <string>
          # local_spi: <string>
          # npu_offload: <value in [disable, enable]>
          # remote_gw: <string>
          # remote_gw6: <string>
          # remote_spi: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey-interface'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_ipsec_manualkeyinterface': {
            'type': 'dict',
            'no_log': False,
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'addr-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['4', '6'], 'type': 'str'},
                'auth-alg': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['null', 'md5', 'sha1', 'sha256', 'sha384', 'sha512'],
                    'type': 'str'
                },
                'auth-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'enc-alg': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['null', 'des', '3des', 'aes128', 'aes192', 'aes256', 'aria128', 'aria192', 'aria256', 'seed'],
                    'type': 'str'
                },
                'enc-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['4', '6'], 'type': 'str'},
                'local-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'local-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'local-spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'npu-offload': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'remote-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ipsec_manualkeyinterface'),
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
