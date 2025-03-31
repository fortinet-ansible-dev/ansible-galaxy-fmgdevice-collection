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
module: fmgd_switchcontroller_lldpprofile
short_description: Configure FortiSwitch LLDP profiles.
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
    switchcontroller_lldpprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            802_1_tlvs:
                aliases: ['802.1-tlvs']
                type: list
                elements: str
                description: Transmitted IEEE 802.
                choices:
                    - 'port-vlan-id'
            802_3_tlvs:
                aliases: ['802.3-tlvs']
                type: list
                elements: str
                description: Transmitted IEEE 802.
                choices:
                    - 'max-frame-size'
                    - 'power-negotiation'
            auto_isl:
                aliases: ['auto-isl']
                type: str
                description: Enable/disable auto inter-switch LAG.
                choices:
                    - 'disable'
                    - 'enable'
            auto_isl_auth:
                aliases: ['auto-isl-auth']
                type: str
                description: Auto inter-switch LAG authentication mode.
                choices:
                    - 'legacy'
                    - 'strict'
                    - 'relax'
            auto_isl_auth_encrypt:
                aliases: ['auto-isl-auth-encrypt']
                type: str
                description: Auto inter-switch LAG encryption mode.
                choices:
                    - 'none'
                    - 'mixed'
                    - 'must'
            auto_isl_auth_identity:
                aliases: ['auto-isl-auth-identity']
                type: str
                description: Auto inter-switch LAG authentication identity.
            auto_isl_auth_macsec_profile:
                aliases: ['auto-isl-auth-macsec-profile']
                type: str
                description: Auto inter-switch LAG macsec profile for encryption.
            auto_isl_auth_reauth:
                aliases: ['auto-isl-auth-reauth']
                type: int
                description: Auto inter-switch LAG authentication reauth period in seconds
            auto_isl_auth_user:
                aliases: ['auto-isl-auth-user']
                type: str
                description: Auto inter-switch LAG authentication user certificate.
            auto_isl_hello_timer:
                aliases: ['auto-isl-hello-timer']
                type: int
                description: Auto inter-switch LAG hello timer duration
            auto_isl_port_group:
                aliases: ['auto-isl-port-group']
                type: int
                description: Auto inter-switch LAG port group ID
            auto_isl_receive_timeout:
                aliases: ['auto-isl-receive-timeout']
                type: int
                description: Auto inter-switch LAG timeout if no response is received
            auto_mclag_icl:
                aliases: ['auto-mclag-icl']
                type: str
                description: Enable/disable MCLAG inter chassis link.
                choices:
                    - 'disable'
                    - 'enable'
            custom_tlvs:
                aliases: ['custom-tlvs']
                type: list
                elements: dict
                description: Custom tlvs.
                suboptions:
                    information_string:
                        aliases: ['information-string']
                        type: str
                        description: Organizationally defined information string
                    name:
                        type: str
                        description: TLV name
                    oui:
                        type: str
                        description: Organizationally unique identifier
                    subtype:
                        type: int
                        description: Organizationally defined subtype
            med_location_service:
                aliases: ['med-location-service']
                type: list
                elements: dict
                description: Med location service.
                suboptions:
                    name:
                        type: str
                        description: Location service type name.
                    status:
                        type: str
                        description: Enable or disable this TLV.
                        choices:
                            - 'disable'
                            - 'enable'
                    sys_location_id:
                        aliases: ['sys-location-id']
                        type: list
                        elements: str
                        description: Location service ID.
            med_network_policy:
                aliases: ['med-network-policy']
                type: list
                elements: dict
                description: Med network policy.
                suboptions:
                    assign_vlan:
                        aliases: ['assign-vlan']
                        type: str
                        description: Enable/disable VLAN assignment when this profile is applied on managed FortiSwitch port.
                        choices:
                            - 'disable'
                            - 'enable'
                    dscp:
                        type: int
                        description: Advertised Differentiated Services Code Point
                    name:
                        type: str
                        description: Policy type name.
                    priority:
                        type: int
                        description: Advertised Layer 2 priority
                    status:
                        type: str
                        description: Enable or disable this TLV.
                        choices:
                            - 'disable'
                            - 'enable'
                    vlan:
                        type: int
                        description: ID of VLAN to advertise, if configured on port
                    vlan_intf:
                        aliases: ['vlan-intf']
                        type: list
                        elements: str
                        description: VLAN interface to advertise; if configured on port.
            med_tlvs:
                aliases: ['med-tlvs']
                type: list
                elements: str
                description: Transmitted LLDP-MED TLVs
                choices:
                    - 'inventory-management'
                    - 'network-policy'
                    - 'power-management'
                    - 'location-identification'
            name:
                type: str
                description: Profile name.
                required: true
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
    - name: Configure FortiSwitch LLDP profiles.
      fortinet.fmgdevice.fmgd_switchcontroller_lldpprofile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_lldpprofile:
          name: "your value" # Required variable, string
          # 802_1_tlvs:
          #   - "port-vlan-id"
          # 802_3_tlvs:
          #   - "max-frame-size"
          #   - "power-negotiation"
          # auto_isl: <value in [disable, enable]>
          # auto_isl_auth: <value in [legacy, strict, relax]>
          # auto_isl_auth_encrypt: <value in [none, mixed, must]>
          # auto_isl_auth_identity: <string>
          # auto_isl_auth_macsec_profile: <string>
          # auto_isl_auth_reauth: <integer>
          # auto_isl_auth_user: <string>
          # auto_isl_hello_timer: <integer>
          # auto_isl_port_group: <integer>
          # auto_isl_receive_timeout: <integer>
          # auto_mclag_icl: <value in [disable, enable]>
          # custom_tlvs:
          #   - information_string: <string>
          #     name: <string>
          #     oui: <string>
          #     subtype: <integer>
          # med_location_service:
          #   - name: <string>
          #     status: <value in [disable, enable]>
          #     sys_location_id: <list or string>
          # med_network_policy:
          #   - assign_vlan: <value in [disable, enable]>
          #     dscp: <integer>
          #     name: <string>
          #     priority: <integer>
          #     status: <value in [disable, enable]>
          #     vlan: <integer>
          #     vlan_intf: <list or string>
          # med_tlvs:
          #   - "inventory-management"
          #   - "network-policy"
          #   - "power-management"
          #   - "location-identification"
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_lldpprofile': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                '802.1-tlvs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'choices': ['port-vlan-id'], 'elements': 'str'},
                '802.3-tlvs': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['max-frame-size', 'power-negotiation'],
                    'elements': 'str'
                },
                'auto-isl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-isl-auth': {'v_range': [['7.4.3', '']], 'choices': ['legacy', 'strict', 'relax'], 'type': 'str'},
                'auto-isl-auth-encrypt': {'v_range': [['7.4.3', '']], 'choices': ['none', 'mixed', 'must'], 'type': 'str'},
                'auto-isl-auth-identity': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'auto-isl-auth-macsec-profile': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'auto-isl-auth-reauth': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'auto-isl-auth-user': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'auto-isl-hello-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-isl-port-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-isl-receive-timeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-mclag-icl': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-tlvs': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'information-string': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'oui': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'subtype': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'med-location-service': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sys-location-id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'med-network-policy': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'assign-vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dscp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'vlan-intf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'med-tlvs': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['inventory-management', 'network-policy', 'power-management', 'location-identification'],
                    'elements': 'str'
                },
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_lldpprofile'),
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
