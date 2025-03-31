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
module: fmgd_user_nacpolicy
short_description: Configure NAC policy matching pattern to identify matching NAC devices.
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
    user_nacpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            category:
                type: str
                description: Category of NAC policy.
                choices:
                    - 'device'
                    - 'firewall-user'
                    - 'ems-tag'
                    - 'vulnerability'
                    - 'fortivoice-tag'
            description:
                type: str
                description: Description for the NAC policy matching pattern.
            ems_tag:
                aliases: ['ems-tag']
                type: list
                elements: str
                description: NAC policy matching EMS tag.
            family:
                type: str
                description:
                    - Support meta variable
                    - NAC policy matching family.
            firewall_address:
                aliases: ['firewall-address']
                type: list
                elements: str
                description: Dynamic firewall address to associate MAC which match this policy.
            fortivoice_tag:
                aliases: ['fortivoice-tag']
                type: list
                elements: str
                description: NAC policy matching FortiVoice tag.
            host:
                type: str
                description: NAC policy matching host.
            hw_vendor:
                aliases: ['hw-vendor']
                type: str
                description:
                    - Support meta variable
                    - NAC policy matching hardware vendor.
            hw_version:
                aliases: ['hw-version']
                type: str
                description: NAC policy matching hardware version.
            mac:
                type: str
                description:
                    - Support meta variable
                    - NAC policy matching MAC address.
            match_period:
                aliases: ['match-period']
                type: int
                description: Number of days the matched devices will be retained
            match_type:
                aliases: ['match-type']
                type: str
                description: Match and retain the devices based on the type.
                choices:
                    - 'dynamic'
                    - 'override'
            name:
                type: str
                description: NAC policy name.
                required: true
            os:
                type: str
                description:
                    - Support meta variable
                    - NAC policy matching operating system.
            severity:
                type: list
                elements: int
                description: NAC policy matching devices vulnerability severity lists.
            src:
                type: str
                description: NAC policy matching source.
            ssid_policy:
                aliases: ['ssid-policy']
                type: list
                elements: str
                description: SSID policy to be applied on the matched NAC policy.
            status:
                type: str
                description: Enable/disable NAC policy.
                choices:
                    - 'disable'
                    - 'enable'
            sw_version:
                aliases: ['sw-version']
                type: str
                description: NAC policy matching software version.
            switch_fortilink:
                aliases: ['switch-fortilink']
                type: list
                elements: str
                description:
                    - Support meta variable
                    - FortiLink interface for which this NAC policy belongs to.
            switch_group:
                aliases: ['switch-group']
                type: list
                elements: str
                description:
                    - Support meta variable
                    - List of managed FortiSwitch groups on which NAC policy can be applied.
            switch_mac_policy:
                aliases: ['switch-mac-policy']
                type: list
                elements: str
                description: Switch MAC policy action to be applied on the matched NAC policy.
            type:
                type: str
                description:
                    - Support meta variable
                    - NAC policy matching type.
            user:
                type: str
                description:
                    - Support meta variable
                    - NAC policy matching user.
            user_group:
                aliases: ['user-group']
                type: list
                elements: str
                description: NAC policy matching user group.
            switch_scope:
                aliases: ['switch-scope']
                type: list
                elements: str
                description: List of managed FortiSwitches on which NAC policy can be applied.
            switch_port_policy:
                aliases: ['switch-port-policy']
                type: list
                elements: str
                description: Switch-port-policy to be applied on the matched NAC policy.
            switch_auto_auth:
                aliases: ['switch-auto-auth']
                type: str
                description: NAC device auto authorization when discovered and nac-policy matched.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'global'
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
    - name: Configure NAC policy matching pattern to identify matching NAC devices.
      fortinet.fmgdevice.fmgd_user_nacpolicy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_nacpolicy:
          name: "your value" # Required variable, string
          # category: <value in [device, firewall-user, ems-tag, ...]>
          # description: <string>
          # ems_tag: <list or string>
          # family: <string>
          # firewall_address: <list or string>
          # fortivoice_tag: <list or string>
          # host: <string>
          # hw_vendor: <string>
          # hw_version: <string>
          # mac: <string>
          # match_period: <integer>
          # match_type: <value in [dynamic, override]>
          # os: <string>
          # severity: <list or integer>
          # src: <string>
          # ssid_policy: <list or string>
          # status: <value in [disable, enable]>
          # sw_version: <string>
          # switch_fortilink: <list or string>
          # switch_group: <list or string>
          # switch_mac_policy: <list or string>
          # type: <string>
          # user: <string>
          # user_group: <list or string>
          # switch_scope: <list or string>
          # switch_port_policy: <list or string>
          # switch_auto_auth: <value in [disable, enable, global]>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_nacpolicy': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'category': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['device', 'firewall-user', 'ems-tag', 'vulnerability', 'fortivoice-tag'],
                    'type': 'str'
                },
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ems-tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'family': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'firewall-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fortivoice-tag': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'host': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'hw-vendor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'hw-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'match-period': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'match-type': {'v_range': [['7.4.3', '']], 'choices': ['dynamic', 'override'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'os': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'severity': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'src': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ssid-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sw-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'switch-fortilink': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'switch-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'switch-mac-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'user': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'user-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'switch-scope': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'switch-port-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'switch-auto-auth': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'global'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_nacpolicy'),
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
