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
module: fmgd_system_fabricvpn
short_description: Setup for self orchestrated fabric auto discovery VPN.
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
    system_fabricvpn:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            advertised_subnets:
                aliases: ['advertised-subnets']
                type: list
                elements: dict
                description: Advertised subnets.
                suboptions:
                    access:
                        type: str
                        description: Access policy direction.
                        choices:
                            - 'inbound'
                            - 'bidirectional'
                    bgp_network:
                        aliases: ['bgp-network']
                        type: list
                        elements: str
                        description: Underlying BGP network.
                    firewall_address:
                        aliases: ['firewall-address']
                        type: list
                        elements: str
                        description: Underlying firewall address.
                    id:
                        type: int
                        description: ID.
                    policies:
                        type: list
                        elements: str
                        description: Underlying policies.
                    prefix:
                        type: list
                        elements: str
                        description: Network prefix.
            bgp_as:
                aliases: ['bgp-as']
                type: int
                description: BGP Router AS number, valid from 1 to 4294967295.
            branch_name:
                aliases: ['branch-name']
                type: str
                description: Branch name.
            health_checks:
                aliases: ['health-checks']
                type: list
                elements: str
                description: Underlying health checks.
            loopback_address_block:
                aliases: ['loopback-address-block']
                type: list
                elements: str
                description: IPv4 address and subnet mask for hubs loopback address, syntax
            loopback_advertised_subnet:
                aliases: ['loopback-advertised-subnet']
                type: list
                elements: str
                description: Loopback advertised subnet reference.
            loopback_interface:
                aliases: ['loopback-interface']
                type: list
                elements: str
                description: Loopback interface.
            overlays:
                type: list
                elements: dict
                description: Overlays.
                suboptions:
                    bgp_neighbor:
                        aliases: ['bgp-neighbor']
                        type: list
                        elements: str
                        description: Underlying BGP neighbor entry.
                    bgp_neighbor_group:
                        aliases: ['bgp-neighbor-group']
                        type: list
                        elements: str
                        description: Underlying BGP neighbor group entry.
                    bgp_neighbor_range:
                        aliases: ['bgp-neighbor-range']
                        type: list
                        elements: str
                        description: Underlying BGP neighbor range entry.
                    bgp_network:
                        aliases: ['bgp-network']
                        type: list
                        elements: str
                        description: Underlying BGP network.
                    interface:
                        type: list
                        elements: str
                        description: Underlying interface name.
                    ipsec_phase1:
                        aliases: ['ipsec-phase1']
                        type: list
                        elements: str
                        description: IPsec interface.
                    name:
                        type: str
                        description: Overlay name.
                    overlay_policy:
                        aliases: ['overlay-policy']
                        type: list
                        elements: str
                        description: The overlay policy to allow ADVPN thru traffic.
                    overlay_tunnel_block:
                        aliases: ['overlay-tunnel-block']
                        type: list
                        elements: str
                        description: IPv4 address and subnet mask for the overlay tunnel , syntax
                    remote_gw:
                        aliases: ['remote-gw']
                        type: str
                        description: IP address of the hub gateway
                    route_policy:
                        aliases: ['route-policy']
                        type: list
                        elements: str
                        description: Underlying router policy.
                    sdwan_member:
                        aliases: ['sdwan-member']
                        type: list
                        elements: str
                        description: Reference to SD-WAN member entry.
            policy_rule:
                aliases: ['policy-rule']
                type: str
                description: Policy creation rule.
                choices:
                    - 'health-check'
                    - 'manual'
                    - 'auto'
            populated:
                type: int
                description: Populated the setting in tables.
            psksecret:
                type: list
                elements: str
                description: Pre-shared secret for ADVPN.
            sdwan_zone:
                aliases: ['sdwan-zone']
                type: list
                elements: str
                description: Reference to created SD-WAN zone.
            status:
                type: str
                description: Enable/disable Fabric VPN.
                choices:
                    - 'disable'
                    - 'enable'
            sync_mode:
                aliases: ['sync-mode']
                type: str
                description: Setting synchronised by fabric or manual.
                choices:
                    - 'disable'
                    - 'enable'
            vpn_role:
                aliases: ['vpn-role']
                type: str
                description: Fabric VPN role.
                choices:
                    - 'hub'
                    - 'spoke'
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
    - name: Setup for self orchestrated fabric auto discovery VPN.
      fortinet.fmgdevice.fmgd_system_fabricvpn:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_fabricvpn:
          # advertised_subnets:
          #   - access: <value in [inbound, bidirectional]>
          #     bgp_network: <list or string>
          #     firewall_address: <list or string>
          #     id: <integer>
          #     policies: <list or string>
          #     prefix: <list or string>
          # bgp_as: <integer>
          # branch_name: <string>
          # health_checks: <list or string>
          # loopback_address_block: <list or string>
          # loopback_advertised_subnet: <list or string>
          # loopback_interface: <list or string>
          # overlays:
          #   - bgp_neighbor: <list or string>
          #     bgp_neighbor_group: <list or string>
          #     bgp_neighbor_range: <list or string>
          #     bgp_network: <list or string>
          #     interface: <list or string>
          #     ipsec_phase1: <list or string>
          #     name: <string>
          #     overlay_policy: <list or string>
          #     overlay_tunnel_block: <list or string>
          #     remote_gw: <string>
          #     route_policy: <list or string>
          #     sdwan_member: <list or string>
          # policy_rule: <value in [health-check, manual, auto]>
          # populated: <integer>
          # psksecret: <list or string>
          # sdwan_zone: <list or string>
          # status: <value in [disable, enable]>
          # sync_mode: <value in [disable, enable]>
          # vpn_role: <value in [hub, spoke]>
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
        '/pm/config/device/{device}/global/system/fabric-vpn'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_fabricvpn': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'advertised-subnets': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['inbound', 'bidirectional'], 'type': 'str'},
                        'bgp-network': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'firewall-address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'policies': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'bgp-as': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'branch-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'health-checks': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'loopback-address-block': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'loopback-advertised-subnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'loopback-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'overlays': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'bgp-neighbor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bgp-neighbor-group': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bgp-neighbor-range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'bgp-network': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'ipsec-phase1': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'overlay-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'overlay-tunnel-block': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'remote-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'route-policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sdwan-member': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'policy-rule': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['health-check', 'manual', 'auto'], 'type': 'str'},
                'populated': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'psksecret': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'sdwan-zone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sync-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vpn-role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['hub', 'spoke'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_fabricvpn'),
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
