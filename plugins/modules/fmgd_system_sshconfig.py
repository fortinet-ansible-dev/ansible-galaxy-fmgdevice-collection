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
module: fmgd_system_sshconfig
short_description: Configure SSH config.
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
    system_sshconfig:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            ssh_enc_algo:
                aliases: ['ssh-enc-algo']
                type: list
                elements: str
                description: Select one or more SSH ciphers.
                choices:
                    - 'chacha20-poly1305@openssh.com'
                    - 'aes128-ctr'
                    - 'aes192-ctr'
                    - 'aes256-ctr'
                    - 'arcfour256'
                    - 'arcfour128'
                    - 'aes128-cbc'
                    - '3des-cbc'
                    - 'blowfish-cbc'
                    - 'cast128-cbc'
                    - 'aes192-cbc'
                    - 'aes256-cbc'
                    - 'arcfour'
                    - 'rijndael-cbc@lysator.liu.se'
                    - 'aes128-gcm@openssh.com'
                    - 'aes256-gcm@openssh.com'
            ssh_hsk:
                aliases: ['ssh-hsk']
                type: str
                description: Config SSH host key.
            ssh_hsk_algo:
                aliases: ['ssh-hsk-algo']
                type: list
                elements: str
                description: Select one or more SSH hostkey algorithms.
                choices:
                    - 'ssh-rsa'
                    - 'ecdsa-sha2-nistp521'
                    - 'rsa-sha2-256'
                    - 'rsa-sha2-512'
                    - 'ssh-ed25519'
                    - 'ecdsa-sha2-nistp384'
                    - 'ecdsa-sha2-nistp256'
            ssh_hsk_override:
                aliases: ['ssh-hsk-override']
                type: str
                description: Enable/disable SSH host key override in SSH daemon.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_hsk_password:
                aliases: ['ssh-hsk-password']
                type: list
                elements: str
                description: Password for ssh-hostkey.
            ssh_kex_algo:
                aliases: ['ssh-kex-algo']
                type: list
                elements: str
                description: Select one or more SSH kex algorithms.
                choices:
                    - 'diffie-hellman-group1-sha1'
                    - 'diffie-hellman-group14-sha1'
                    - 'diffie-hellman-group-exchange-sha1'
                    - 'diffie-hellman-group-exchange-sha256'
                    - 'curve25519-sha256@libssh.org'
                    - 'ecdh-sha2-nistp256'
                    - 'ecdh-sha2-nistp384'
                    - 'ecdh-sha2-nistp521'
                    - 'diffie-hellman-group14-sha256'
                    - 'diffie-hellman-group16-sha512'
                    - 'diffie-hellman-group18-sha512'
            ssh_mac_algo:
                aliases: ['ssh-mac-algo']
                type: list
                elements: str
                description: Select one or more SSH MAC algorithms.
                choices:
                    - 'hmac-md5'
                    - 'hmac-md5-etm@openssh.com'
                    - 'hmac-md5-96'
                    - 'hmac-md5-96-etm@openssh.com'
                    - 'hmac-sha1'
                    - 'hmac-sha1-etm@openssh.com'
                    - 'hmac-sha2-256'
                    - 'hmac-sha2-256-etm@openssh.com'
                    - 'hmac-sha2-512'
                    - 'hmac-sha2-512-etm@openssh.com'
                    - 'hmac-ripemd160'
                    - 'hmac-ripemd160@openssh.com'
                    - 'hmac-ripemd160-etm@openssh.com'
                    - 'umac-64@openssh.com'
                    - 'umac-128@openssh.com'
                    - 'umac-64-etm@openssh.com'
                    - 'umac-128-etm@openssh.com'
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
    - name: Configure SSH config.
      fortinet.fmgdevice.fmgd_system_sshconfig:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_sshconfig:
          # ssh_enc_algo:
          #   - "chacha20-poly1305@openssh.com"
          #   - "aes128-ctr"
          #   - "aes192-ctr"
          #   - "aes256-ctr"
          #   - "arcfour256"
          #   - "arcfour128"
          #   - "aes128-cbc"
          #   - "3des-cbc"
          #   - "blowfish-cbc"
          #   - "cast128-cbc"
          #   - "aes192-cbc"
          #   - "aes256-cbc"
          #   - "arcfour"
          #   - "rijndael-cbc@lysator.liu.se"
          #   - "aes128-gcm@openssh.com"
          #   - "aes256-gcm@openssh.com"
          # ssh_hsk: <string>
          # ssh_hsk_algo:
          #   - "ssh-rsa"
          #   - "ecdsa-sha2-nistp521"
          #   - "rsa-sha2-256"
          #   - "rsa-sha2-512"
          #   - "ssh-ed25519"
          #   - "ecdsa-sha2-nistp384"
          #   - "ecdsa-sha2-nistp256"
          # ssh_hsk_override: <value in [disable, enable]>
          # ssh_hsk_password: <list or string>
          # ssh_kex_algo:
          #   - "diffie-hellman-group1-sha1"
          #   - "diffie-hellman-group14-sha1"
          #   - "diffie-hellman-group-exchange-sha1"
          #   - "diffie-hellman-group-exchange-sha256"
          #   - "curve25519-sha256@libssh.org"
          #   - "ecdh-sha2-nistp256"
          #   - "ecdh-sha2-nistp384"
          #   - "ecdh-sha2-nistp521"
          #   - "diffie-hellman-group14-sha256"
          #   - "diffie-hellman-group16-sha512"
          #   - "diffie-hellman-group18-sha512"
          # ssh_mac_algo:
          #   - "hmac-md5"
          #   - "hmac-md5-etm@openssh.com"
          #   - "hmac-md5-96"
          #   - "hmac-md5-96-etm@openssh.com"
          #   - "hmac-sha1"
          #   - "hmac-sha1-etm@openssh.com"
          #   - "hmac-sha2-256"
          #   - "hmac-sha2-256-etm@openssh.com"
          #   - "hmac-sha2-512"
          #   - "hmac-sha2-512-etm@openssh.com"
          #   - "hmac-ripemd160"
          #   - "hmac-ripemd160@openssh.com"
          #   - "hmac-ripemd160-etm@openssh.com"
          #   - "umac-64@openssh.com"
          #   - "umac-128@openssh.com"
          #   - "umac-64-etm@openssh.com"
          #   - "umac-128-etm@openssh.com"
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
        '/pm/config/device/{device}/global/system/ssh-config'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_sshconfig': {
            'type': 'dict',
            'v_range': [['7.4.3', '']],
            'options': {
                'ssh-enc-algo': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'arcfour256', 'arcfour128', 'aes128-cbc', '3des-cbc',
                        'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'rijndael-cbc@lysator.liu.se', 'aes128-gcm@openssh.com',
                        'aes256-gcm@openssh.com'
                    ],
                    'elements': 'str'
                },
                'ssh-hsk': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'ssh-hsk-algo': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'ssh-rsa', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256'
                    ],
                    'elements': 'str'
                },
                'ssh-hsk-override': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-hsk-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'ssh-kex-algo': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1',
                        'diffie-hellman-group-exchange-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384',
                        'ecdh-sha2-nistp521', 'diffie-hellman-group14-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512'
                    ],
                    'elements': 'str'
                },
                'ssh-mac-algo': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'hmac-md5', 'hmac-md5-etm@openssh.com', 'hmac-md5-96', 'hmac-md5-96-etm@openssh.com', 'hmac-sha1', 'hmac-sha1-etm@openssh.com',
                        'hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-512-etm@openssh.com', 'hmac-ripemd160',
                        'hmac-ripemd160@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com',
                        'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com'
                    ],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sshconfig'),
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
