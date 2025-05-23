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
module: fmgd_switchcontroller_dynamicportpolicy
short_description: Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
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
    switchcontroller_dynamicportpolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            description:
                type: str
                description: Description for the Dynamic port policy.
            fortilink:
                type: list
                elements: str
                description: FortiLink interface for which this Dynamic port policy belongs to.
            name:
                type: str
                description: Dynamic port policy name.
                required: true
            policy:
                type: list
                elements: dict
                description: Policy.
                suboptions:
                    802_1x:
                        aliases: ['802-1x']
                        type: list
                        elements: str
                        description: '802.'
                    bounce_port_link:
                        aliases: ['bounce-port-link']
                        type: str
                        description: Enable/disable bouncing
                        choices:
                            - 'disable'
                            - 'enable'
                    category:
                        type: str
                        description: Category of Dynamic port policy.
                        choices:
                            - 'device'
                            - 'interface-tag'
                    description:
                        type: str
                        description: Description for the policy.
                    family:
                        type: str
                        description: Match policy based on family.
                    host:
                        type: str
                        description: Match policy based on host.
                    hw_vendor:
                        aliases: ['hw-vendor']
                        type: str
                        description: Match policy based on hardware vendor.
                    interface_tags:
                        aliases: ['interface-tags']
                        type: list
                        elements: str
                        description: Match policy based on the FortiSwitch interface object tags.
                    lldp_profile:
                        aliases: ['lldp-profile']
                        type: list
                        elements: str
                        description: LLDP profile to be applied when using this policy.
                    mac:
                        type: str
                        description: Match policy based on MAC address.
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
                        description: Policy name.
                    qos_policy:
                        aliases: ['qos-policy']
                        type: list
                        elements: str
                        description: QoS policy to be applied when using this policy.
                    status:
                        type: str
                        description: Enable/disable policy.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: Match policy based on type.
                    vlan_policy:
                        aliases: ['vlan-policy']
                        type: list
                        elements: str
                        description: VLAN policy to be applied when using this policy.
                    bounce_port_duration:
                        aliases: ['bounce-port-duration']
                        type: int
                        description: Bounce duration in seconds of a switch port where this policy is applied.
                    poe_reset:
                        aliases: ['poe-reset']
                        type: str
                        description: Enable/disable POE reset of a switch port where this policy is applied.
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
    - name: Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
      fortinet.fmgdevice.fmgd_switchcontroller_dynamicportpolicy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_dynamicportpolicy:
          name: "your value" # Required variable, string
          # description: <string>
          # fortilink: <list or string>
          # policy:
          #   - 802_1x: <list or string>
          #     bounce_port_link: <value in [disable, enable]>
          #     category: <value in [device, interface-tag]>
          #     description: <string>
          #     family: <string>
          #     host: <string>
          #     hw_vendor: <string>
          #     interface_tags: <list or string>
          #     lldp_profile: <list or string>
          #     mac: <string>
          #     match_period: <integer>
          #     match_type: <value in [dynamic, override]>
          #     name: <string>
          #     qos_policy: <list or string>
          #     status: <value in [disable, enable]>
          #     type: <string>
          #     vlan_policy: <list or string>
          #     bounce_port_duration: <integer>
          #     poe_reset: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_dynamicportpolicy': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fortilink': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'policy': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        '802-1x': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bounce-port-link': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'category': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['device', 'interface-tag'], 'type': 'str'},
                        'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'family': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'host': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'hw-vendor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'interface-tags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'lldp-profile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'mac': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'match-period': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'match-type': {'v_range': [['7.4.3', '']], 'choices': ['dynamic', 'override'], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'qos-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vlan-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bounce-port-duration': {'v_range': [['7.6.2', '']], 'type': 'int'},
                        'poe-reset': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_dynamicportpolicy'),
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
