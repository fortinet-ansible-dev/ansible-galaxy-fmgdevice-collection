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
module: fmgd_system_gretunnel
short_description: Configure GRE tunnel.
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
    system_gretunnel:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            auto_asic_offload:
                aliases: ['auto-asic-offload']
                type: str
                description: Enable/disable automatic ASIC offloading.
                choices:
                    - 'disable'
                    - 'enable'
            checksum_reception:
                aliases: ['checksum-reception']
                type: str
                description: Enable/disable validating checksums in received GRE packets.
                choices:
                    - 'disable'
                    - 'enable'
            checksum_transmission:
                aliases: ['checksum-transmission']
                type: str
                description: Enable/disable including checksums in transmitted GRE packets.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode:
                type: str
                description: DiffServ setting to be applied to GRE tunnel outer IP header.
            dscp_copying:
                aliases: ['dscp-copying']
                type: str
                description: Enable/disable DSCP copying.
                choices:
                    - 'disable'
                    - 'enable'
            interface:
                type: list
                elements: str
                description: Interface name.
            ip_version:
                aliases: ['ip-version']
                type: str
                description: IP version to use for VPN interface.
                choices:
                    - '4'
                    - '6'
            keepalive_failtimes:
                aliases: ['keepalive-failtimes']
                type: int
                description: Number of consecutive unreturned keepalive messages before a GRE connection is considered down
            keepalive_interval:
                aliases: ['keepalive-interval']
                type: int
                description: Keepalive message interval
            key_inbound:
                aliases: ['key-inbound']
                type: int
                description: Require received GRE packets contain this key
            key_outbound:
                aliases: ['key-outbound']
                type: int
                description: Include this key in transmitted GRE packets
            local_gw:
                aliases: ['local-gw']
                type: str
                description: IP address of the local gateway.
            local_gw6:
                aliases: ['local-gw6']
                type: str
                description: IPv6 address of the local gateway.
            name:
                type: str
                description: Tunnel name.
                required: true
            remote_gw:
                aliases: ['remote-gw']
                type: str
                description: IP address of the remote gateway.
            remote_gw6:
                aliases: ['remote-gw6']
                type: str
                description: IPv6 address of the remote gateway.
            sequence_number_reception:
                aliases: ['sequence-number-reception']
                type: str
                description: Enable/disable validating sequence numbers in received GRE packets.
                choices:
                    - 'disable'
                    - 'enable'
            sequence_number_transmission:
                aliases: ['sequence-number-transmission']
                type: str
                description: Enable/disable including of sequence numbers in transmitted GRE packets.
                choices:
                    - 'disable'
                    - 'enable'
            use_sdwan:
                aliases: ['use-sdwan']
                type: str
                description: Enable/disable use of SD-WAN to reach remote gateway.
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
    - name: Configure GRE tunnel.
      fortinet.fmgdevice.fmgd_system_gretunnel:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        system_gretunnel:
          name: "your value" # Required variable, string
          # auto_asic_offload: <value in [disable, enable]>
          # checksum_reception: <value in [disable, enable]>
          # checksum_transmission: <value in [disable, enable]>
          # diffservcode: <string>
          # dscp_copying: <value in [disable, enable]>
          # interface: <list or string>
          # ip_version: <value in [4, 6]>
          # keepalive_failtimes: <integer>
          # keepalive_interval: <integer>
          # key_inbound: <integer>
          # key_outbound: <integer>
          # local_gw: <string>
          # local_gw6: <string>
          # remote_gw: <string>
          # remote_gw6: <string>
          # sequence_number_reception: <value in [disable, enable]>
          # sequence_number_transmission: <value in [disable, enable]>
          # use_sdwan: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/gre-tunnel'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_gretunnel': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'auto-asic-offload': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'checksum-reception': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'checksum-transmission': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'dscp-copying': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ip-version': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['4', '6'], 'type': 'str'},
                'keepalive-failtimes': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'keepalive-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'key-inbound': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'key-outbound': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'local-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'local-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'remote-gw': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'remote-gw6': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'sequence-number-reception': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sequence-number-transmission': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'use-sdwan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_gretunnel'),
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
