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
module: fmgd_vpn_ocvpn
short_description: Configure Overlay Controller VPN settings.
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
    vpn_ocvpn:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_discovery:
                aliases: ['auto-discovery']
                type: str
                description: Enable/disable auto-discovery shortcuts.
                choices:
                    - 'disable'
                    - 'enable'
            auto_discovery_shortcut_mode:
                aliases: ['auto-discovery-shortcut-mode']
                type: str
                description: Control deletion of child short-cut tunnels when the parent tunnel goes down.
                choices:
                    - 'independent'
                    - 'dependent'
            eap:
                type: str
                description: Enable/disable EAP client authentication.
                choices:
                    - 'disable'
                    - 'enable'
            eap_users:
                aliases: ['eap-users']
                type: list
                elements: str
                description: EAP authentication user group.
            forticlient_access:
                aliases: ['forticlient-access']
                type: dict
                description: Forticlient access.
                suboptions:
                    auth_groups:
                        aliases: ['auth-groups']
                        type: list
                        elements: dict
                        description: Auth groups.
                        suboptions:
                            auth_group:
                                aliases: ['auth-group']
                                type: list
                                elements: str
                                description: Authentication user group for FortiClient access.
                            name:
                                type: str
                                description: Group name.
                            overlays:
                                type: list
                                elements: str
                                description: OCVPN overlays to allow access to.
                    psksecret:
                        type: list
                        elements: str
                        description: Pre-shared secret for FortiClient PSK authentication
                    status:
                        type: str
                        description: Enable/disable FortiClient to access OCVPN networks.
                        choices:
                            - 'disable'
                            - 'enable'
            ha_alias:
                aliases: ['ha-alias']
                type: str
                description: Hidden HA alias.
            ip_allocation_block:
                aliases: ['ip-allocation-block']
                type: list
                elements: str
                description: Class B subnet reserved for private IP address assignment.
            multipath:
                type: str
                description: Enable/disable multipath redundancy.
                choices:
                    - 'disable'
                    - 'enable'
            nat:
                type: str
                description: Enable/disable NAT support.
                choices:
                    - 'disable'
                    - 'enable'
            overlays:
                type: list
                elements: dict
                description: Overlays.
                suboptions:
                    inter_overlay:
                        aliases: ['inter-overlay']
                        type: str
                        description: Allow or deny traffic from other overlays.
                        choices:
                            - 'deny'
                            - 'allow'
                    overlay_name:
                        aliases: ['overlay-name']
                        type: str
                        description: Overlay name.
                    subnets:
                        type: list
                        elements: dict
                        description: Subnets.
                        suboptions:
                            id:
                                type: int
                                description: ID.
                            interface:
                                type: list
                                elements: str
                                description: LAN interface.
                            subnet:
                                type: list
                                elements: str
                                description: IPv4 address and subnet mask.
                            type:
                                type: str
                                description: Subnet type.
                                choices:
                                    - 'subnet'
                                    - 'interface'
                    ipv4_start_ip:
                        aliases: ['ipv4-start-ip']
                        type: str
                        description: Start of IPv4 range.
                    ipv4_end_ip:
                        aliases: ['ipv4-end-ip']
                        type: str
                        description: End of IPv4 range.
                    assign_ip:
                        aliases: ['assign-ip']
                        type: str
                        description: Enable/disable mode-cfg address assignment.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: ID.
                    name:
                        type: str
                        description: Overlay name.
            poll_interval:
                aliases: ['poll-interval']
                type: int
                description: Overlay Controller VPN polling interval.
            role:
                type: str
                description: Set device role.
                choices:
                    - 'spoke'
                    - 'primary-hub'
                    - 'secondary-hub'
                    - 'client'
            sdwan:
                type: str
                description: Enable/disable adding OCVPN tunnels to SD-WAN.
                choices:
                    - 'disable'
                    - 'enable'
            sdwan_zone:
                aliases: ['sdwan-zone']
                type: list
                elements: str
                description: Set SD-WAN zone.
            status:
                type: str
                description: Enable/disable Overlay Controller cloud assisted VPN.
                choices:
                    - 'disable'
                    - 'enable'
            wan_interface:
                aliases: ['wan-interface']
                type: list
                elements: str
                description: FortiGate WAN interfaces to use with OCVPN.
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
    - name: Configure Overlay Controller VPN settings.
      fortinet.fmgdevice.fmgd_vpn_ocvpn:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        vpn_ocvpn:
          # auto_discovery: <value in [disable, enable]>
          # auto_discovery_shortcut_mode: <value in [independent, dependent]>
          # eap: <value in [disable, enable]>
          # eap_users: <list or string>
          # forticlient_access:
          #   auth_groups:
          #     - auth_group: <list or string>
          #       name: <string>
          #       overlays: <list or string>
          #   psksecret: <list or string>
          #   status: <value in [disable, enable]>
          # ha_alias: <string>
          # ip_allocation_block: <list or string>
          # multipath: <value in [disable, enable]>
          # nat: <value in [disable, enable]>
          # overlays:
          #   - inter_overlay: <value in [deny, allow]>
          #     overlay_name: <string>
          #     subnets:
          #       - id: <integer>
          #         interface: <list or string>
          #         subnet: <list or string>
          #         type: <value in [subnet, interface]>
          #     ipv4_start_ip: <string>
          #     ipv4_end_ip: <string>
          #     assign_ip: <value in [disable, enable]>
          #     id: <integer>
          #     name: <string>
          # poll_interval: <integer>
          # role: <value in [spoke, primary-hub, secondary-hub, ...]>
          # sdwan: <value in [disable, enable]>
          # sdwan_zone: <list or string>
          # status: <value in [disable, enable]>
          # wan_interface: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_ocvpn': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'auto-discovery': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'auto-discovery-shortcut-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['independent', 'dependent'], 'type': 'str'},
                'eap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eap-users': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'forticlient-access': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'auth-groups': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'auth-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                                'overlays': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'psksecret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ha-alias': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ip-allocation-block': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'multipath': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'overlays': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'inter-overlay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'allow'], 'type': 'str'},
                        'overlay-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'subnets': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['subnet', 'interface'], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'ipv4-start-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'ipv4-end-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'assign-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'poll-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['spoke', 'primary-hub', 'secondary-hub', 'client'], 'type': 'str'},
                'sdwan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sdwan-zone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wan-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_ocvpn'),
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
