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
module: fmgd_system_mobiletunnel
short_description: Configure Mobile tunnels, an implementation of Network Mobility
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
    system_mobiletunnel:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            hash_algorithm:
                aliases: ['hash-algorithm']
                type: str
                description: Hash Algorithm
                choices:
                    - 'hmac-md5'
            home_address:
                aliases: ['home-address']
                type: str
                description: Home IP address
            home_agent:
                aliases: ['home-agent']
                type: str
                description: IPv4 address of the NEMO HA
            lifetime:
                type: int
                description: NMMO HA registration request lifetime
            n_mhae_key:
                aliases: ['n-mhae-key']
                type: list
                elements: str
                description: NEMO authentication key.
            n_mhae_key_type:
                aliases: ['n-mhae-key-type']
                type: str
                description: NEMO authentication key type
                choices:
                    - 'ascii'
                    - 'base64'
            n_mhae_spi:
                aliases: ['n-mhae-spi']
                type: int
                description: NEMO authentication SPI
            name:
                type: str
                description: Tunnel name.
                required: true
            network:
                type: list
                elements: dict
                description: Network.
                suboptions:
                    id:
                        type: int
                        description: Network entry ID.
                    interface:
                        type: list
                        elements: str
                        description: Select the associated interface name from available options.
                    prefix:
                        type: list
                        elements: str
                        description: Class IP and Netmask with correction
            reg_interval:
                aliases: ['reg-interval']
                type: int
                description: NMMO HA registration interval
            reg_retry:
                aliases: ['reg-retry']
                type: int
                description: Maximum number of NMMO HA registration retries
            renew_interval:
                aliases: ['renew-interval']
                type: int
                description: Time before lifetime expiration to send NMMO HA re-registration
            roaming_interface:
                aliases: ['roaming-interface']
                type: list
                elements: str
                description: Select the associated interface name from available options.
            status:
                type: str
                description: Enable/disable this mobile tunnel.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_mode:
                aliases: ['tunnel-mode']
                type: str
                description: NEMO tunnel mode
                choices:
                    - 'gre'
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
    - name: Configure Mobile tunnels, an implementation of Network Mobility
      fortinet.fmgdevice.fmgd_system_mobiletunnel:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_mobiletunnel:
          name: "your value" # Required variable, string
          # hash_algorithm: <value in [hmac-md5]>
          # home_address: <string>
          # home_agent: <string>
          # lifetime: <integer>
          # n_mhae_key: <list or string>
          # n_mhae_key_type: <value in [ascii, base64]>
          # n_mhae_spi: <integer>
          # network:
          #   - id: <integer>
          #     interface: <list or string>
          #     prefix: <list or string>
          # reg_interval: <integer>
          # reg_retry: <integer>
          # renew_interval: <integer>
          # roaming_interface: <list or string>
          # status: <value in [disable, enable]>
          # tunnel_mode: <value in [gre]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_mobiletunnel': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'hash-algorithm': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['hmac-md5'], 'type': 'str'},
                'home-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'home-agent': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'lifetime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'n-mhae-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'n-mhae-key-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ascii', 'base64'], 'type': 'str'},
                'n-mhae-spi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'network': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'reg-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'reg-retry': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'renew-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'roaming-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['gre'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_mobiletunnel'),
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
