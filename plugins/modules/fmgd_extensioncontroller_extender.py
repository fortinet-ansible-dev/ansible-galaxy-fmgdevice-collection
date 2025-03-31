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
module: fmgd_extensioncontroller_extender
short_description: Extender controller configuration.
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
    extensioncontroller_extender:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            allowaccess:
                type: list
                elements: str
                description: Control management access to the managed extender.
                choices:
                    - 'https'
                    - 'ping'
                    - 'ssh'
                    - 'snmp'
                    - 'http'
                    - 'telnet'
            authorized:
                type: str
                description: FortiExtender Administration
                choices:
                    - 'disable'
                    - 'enable'
                    - 'discovered'
            bandwidth_limit:
                aliases: ['bandwidth-limit']
                type: int
                description: FortiExtender LAN extension bandwidth limit
            description:
                type: str
                description: Description.
            device_id:
                aliases: ['device-id']
                type: int
                description: Device ID.
            enforce_bandwidth:
                aliases: ['enforce-bandwidth']
                type: str
                description: Enable/disable enforcement of bandwidth on LAN extension interface.
                choices:
                    - 'disable'
                    - 'enable'
            ext_name:
                aliases: ['ext-name']
                type: str
                description: FortiExtender name.
            extension_type:
                aliases: ['extension-type']
                type: str
                description: Extension type for this FortiExtender.
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            firmware_provision_latest:
                aliases: ['firmware-provision-latest']
                type: str
                description: Enable/disable one-time automatic provisioning of the latest firmware version.
                choices:
                    - 'disable'
                    - 'once'
            id:
                type: str
                description: FortiExtender serial number.
            login_password:
                aliases: ['login-password']
                type: list
                elements: str
                description: Set the managed extenders administrator password.
            login_password_change:
                aliases: ['login-password-change']
                type: str
                description: Change or reset the administrator password of a managed extender
                choices:
                    - 'no'
                    - 'yes'
                    - 'default'
            name:
                type: str
                description: FortiExtender entry name.
                required: true
            override_allowaccess:
                aliases: ['override-allowaccess']
                type: str
                description: Enable to override the extender profile management access configuration.
                choices:
                    - 'disable'
                    - 'enable'
            override_enforce_bandwidth:
                aliases: ['override-enforce-bandwidth']
                type: str
                description: Enable to override the extender profile enforce-bandwidth setting.
                choices:
                    - 'disable'
                    - 'enable'
            override_login_password_change:
                aliases: ['override-login-password-change']
                type: str
                description: Enable to override the extender profile login-password
                choices:
                    - 'disable'
                    - 'enable'
            profile:
                type: list
                elements: str
                description: FortiExtender profile configuration.
            vdom:
                type: int
                description: Vdom.
            wan_extension:
                aliases: ['wan-extension']
                type: dict
                description: Wan extension.
                suboptions:
                    modem1_extension:
                        aliases: ['modem1-extension']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem2_extension:
                        aliases: ['modem2-extension']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem1_pdn1_interface:
                        aliases: ['modem1-pdn1-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem1_pdn2_interface:
                        aliases: ['modem1-pdn2-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem1_pdn3_interface:
                        aliases: ['modem1-pdn3-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem1_pdn4_interface:
                        aliases: ['modem1-pdn4-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem2_pdn1_interface:
                        aliases: ['modem2-pdn1-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem2_pdn2_interface:
                        aliases: ['modem2-pdn2-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem2_pdn3_interface:
                        aliases: ['modem2-pdn3-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
                    modem2_pdn4_interface:
                        aliases: ['modem2-pdn4-interface']
                        type: list
                        elements: str
                        description: FortiExtender interface name.
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
    - name: Extender controller configuration.
      fortinet.fmgdevice.fmgd_extensioncontroller_extender:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        extensioncontroller_extender:
          name: "your value" # Required variable, string
          # allowaccess:
          #   - "https"
          #   - "ping"
          #   - "ssh"
          #   - "snmp"
          #   - "http"
          #   - "telnet"
          # authorized: <value in [disable, enable, discovered]>
          # bandwidth_limit: <integer>
          # description: <string>
          # device_id: <integer>
          # enforce_bandwidth: <value in [disable, enable]>
          # ext_name: <string>
          # extension_type: <value in [wan-extension, lan-extension]>
          # firmware_provision_latest: <value in [disable, once]>
          # id: <string>
          # login_password: <list or string>
          # login_password_change: <value in [no, yes, default]>
          # override_allowaccess: <value in [disable, enable]>
          # override_enforce_bandwidth: <value in [disable, enable]>
          # override_login_password_change: <value in [disable, enable]>
          # profile: <list or string>
          # vdom: <integer>
          # wan_extension:
          #   modem1_extension: <list or string>
          #   modem2_extension: <list or string>
          #   modem1_pdn1_interface: <list or string>
          #   modem1_pdn2_interface: <list or string>
          #   modem1_pdn3_interface: <list or string>
          #   modem1_pdn4_interface: <list or string>
          #   modem2_pdn1_interface: <list or string>
          #   modem2_pdn2_interface: <list or string>
          #   modem2_pdn3_interface: <list or string>
          #   modem2_pdn4_interface: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'extensioncontroller_extender': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'allowaccess': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['https', 'ping', 'ssh', 'snmp', 'http', 'telnet'],
                    'elements': 'str'
                },
                'authorized': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'discovered'], 'type': 'str'},
                'bandwidth-limit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'device-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'enforce-bandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ext-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'extension-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['wan-extension', 'lan-extension'], 'type': 'str'},
                'firmware-provision-latest': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'once'], 'type': 'str'},
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'login-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'login-password-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['no', 'yes', 'default'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'override-allowaccess': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-enforce-bandwidth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-login-password-change': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'wan-extension': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'modem1-extension': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'modem2-extension': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'modem1-pdn1-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem1-pdn2-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem1-pdn3-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem1-pdn4-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem2-pdn1-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem2-pdn2-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem2-pdn3-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                        'modem2-pdn4-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
                    }
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extender'),
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
