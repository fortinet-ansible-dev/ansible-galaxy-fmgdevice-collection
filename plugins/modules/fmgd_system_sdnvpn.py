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
module: fmgd_system_sdnvpn
short_description: Configure public cloud VPN service.
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
    system_sdnvpn:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bgp_as:
                aliases: ['bgp-as']
                type: int
                description: BGP Router AS number.
            bgp_from:
                aliases: ['bgp-from']
                type: str
                description: BGP source.
                choices:
                    - 'unset'
                    - 'config'
                    - 'cli'
            bgp_seq:
                aliases: ['bgp-seq']
                type: int
                description: BGP sequence number.
            cgw_gateway:
                aliases: ['cgw-gateway']
                type: str
                description: Public IP address of the customer gateway.
            cgw_name:
                aliases: ['cgw-name']
                type: str
                description: AWS customer gateway name to be created.
            cgw_id:
                type: str
                description: Customer gateway id.
            code:
                type: int
                description: Code.
            internal_interface:
                aliases: ['internal-interface']
                type: list
                elements: str
                description: Internal interface with local subnet.
            local_cidr:
                aliases: ['local-cidr']
                type: list
                elements: str
                description: Local subnet address and subnet mask.
            name:
                type: str
                description: Public cloud VPN name.
                required: true
            nat_traversal:
                aliases: ['nat-traversal']
                type: str
                description: Enable/disable use for NAT traversal.
                choices:
                    - 'disable'
                    - 'enable'
            psksecret:
                type: list
                elements: str
                description: Pre-shared secret for PSK authentication.
            remote_cidr:
                aliases: ['remote-cidr']
                type: list
                elements: str
                description: Remote subnet address and subnet mask.
            remote_type:
                aliases: ['remote-type']
                type: str
                description: Type of remote device.
                choices:
                    - 'vgw'
                    - 'tgw'
            routing_type:
                aliases: ['routing-type']
                type: str
                description: Type of routing.
                choices:
                    - 'static'
                    - 'dynamic'
            sdn:
                type: list
                elements: str
                description: SDN connector name.
            status:
                type: int
                description: Status.
            subnet_id:
                aliases: ['subnet-id']
                type: str
                description: AWS subnet id for TGW route propagation.
            tgw_id:
                aliases: ['tgw-id']
                type: str
                description: Transit gateway id.
            tgw_vpn_rtbl_id:
                type: str
                description: Transit gateway route table id.
            trtbl_attachment:
                type: str
                description: Transit gateway route table attachment id.
            tunnel_interface:
                aliases: ['tunnel-interface']
                type: list
                elements: str
                description: Tunnel interface with public IP.
            type:
                type: int
                description: Type.
            vgw_id:
                aliases: ['vgw-id']
                type: str
                description: Virtual private gateway id.
            vpn_id:
                type: str
                description: VPN connection id.
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
    - name: Configure public cloud VPN service.
      fortinet.fmgdevice.fmgd_system_sdnvpn:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_sdnvpn:
          name: "your value" # Required variable, string
          # bgp_as: <integer>
          # bgp_from: <value in [unset, config, cli]>
          # bgp_seq: <integer>
          # cgw_gateway: <string>
          # cgw_name: <string>
          # cgw_id: <string>
          # code: <integer>
          # internal_interface: <list or string>
          # local_cidr: <list or string>
          # nat_traversal: <value in [disable, enable]>
          # psksecret: <list or string>
          # remote_cidr: <list or string>
          # remote_type: <value in [vgw, tgw]>
          # routing_type: <value in [static, dynamic]>
          # sdn: <list or string>
          # status: <integer>
          # subnet_id: <string>
          # tgw_id: <string>
          # tgw_vpn_rtbl_id: <string>
          # trtbl_attachment: <string>
          # tunnel_interface: <list or string>
          # type: <integer>
          # vgw_id: <string>
          # vpn_id: <string>
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
        '/pm/config/device/{device}/global/system/sdn-vpn'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_sdnvpn': {
            'type': 'dict',
            'v_range': [['7.6.2', '']],
            'options': {
                'bgp-as': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'bgp-from': {'v_range': [['7.6.2', '']], 'choices': ['unset', 'config', 'cli'], 'type': 'str'},
                'bgp-seq': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'cgw-gateway': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'cgw-name': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'cgw_id': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'code': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'internal-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'local-cidr': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'name': {'v_range': [['7.6.2', '']], 'required': True, 'type': 'str'},
                'nat-traversal': {'v_range': [['7.6.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'psksecret': {'v_range': [['7.6.2', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'remote-cidr': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'remote-type': {'v_range': [['7.6.2', '']], 'choices': ['vgw', 'tgw'], 'type': 'str'},
                'routing-type': {'v_range': [['7.6.2', '']], 'choices': ['static', 'dynamic'], 'type': 'str'},
                'sdn': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'subnet-id': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'tgw-id': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'tgw_vpn_rtbl_id': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'trtbl_attachment': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'tunnel-interface': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'type': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'vgw-id': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'vpn_id': {'v_range': [['7.6.2', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnvpn'),
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
