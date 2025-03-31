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
module: fmgd_system_pcpserver
short_description: Configure PCP server information.
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
    system_pcpserver:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            pools:
                type: list
                elements: dict
                description: Pools.
                suboptions:
                    allow_opcode:
                        aliases: ['allow-opcode']
                        type: list
                        elements: str
                        description: Allowed PCP opcode.
                        choices:
                            - 'map'
                            - 'peer'
                            - 'announce'
                    announcement_count:
                        aliases: ['announcement-count']
                        type: int
                        description: Number of multicast announcements.
                    arp_reply:
                        aliases: ['arp-reply']
                        type: str
                        description: Enable to respond to ARP requests for external IP
                        choices:
                            - 'disable'
                            - 'enable'
                    client_mapping_limit:
                        aliases: ['client-mapping-limit']
                        type: int
                        description: Mapping limit per client
                    client_subnet:
                        aliases: ['client-subnet']
                        type: list
                        elements: str
                        description: Subnets from which PCP requests are accepted.
                    description:
                        type: str
                        description: Description.
                    ext_intf:
                        aliases: ['ext-intf']
                        type: list
                        elements: str
                        description: External interface name.
                    extip:
                        type: str
                        description: IP address or address range on the external interface that you want to map to an address on the internal network.
                    extport:
                        type: str
                        description: Incoming port number range that you want to map to a port number on the internal network.
                    id:
                        type: int
                        description: ID.
                    intl_intf:
                        aliases: ['intl-intf']
                        type: list
                        elements: str
                        description: Internal interface name.
                    mapping_filter_limit:
                        aliases: ['mapping-filter-limit']
                        type: int
                        description: Filter limit per mapping
                    maximal_lifetime:
                        aliases: ['maximal-lifetime']
                        type: int
                        description: Maximal lifetime of a PCP mapping in seconds
                    minimal_lifetime:
                        aliases: ['minimal-lifetime']
                        type: int
                        description: Minimal lifetime of a PCP mapping in seconds
                    multicast_announcement:
                        aliases: ['multicast-announcement']
                        type: str
                        description: Enable/disable multicast announcements.
                        choices:
                            - 'disable'
                            - 'enable'
                    name:
                        type: str
                        description: PCP pool name.
                    recycle_delay:
                        aliases: ['recycle-delay']
                        type: int
                        description: Minimum delay
                    third_party:
                        aliases: ['third-party']
                        type: str
                        description: Allow/disallow third party option.
                        choices:
                            - 'disallow'
                            - 'allow'
                    third_party_subnet:
                        aliases: ['third-party-subnet']
                        type: list
                        elements: str
                        description: Subnets from which third party requests are accepted.
            status:
                type: str
                description: Enable/disable PCP server.
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
    - name: Configure PCP server information.
      fortinet.fmgdevice.fmgd_system_pcpserver:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        system_pcpserver:
          # pools:
          #   - allow_opcode:
          #       - "map"
          #       - "peer"
          #       - "announce"
          #     announcement_count: <integer>
          #     arp_reply: <value in [disable, enable]>
          #     client_mapping_limit: <integer>
          #     client_subnet: <list or string>
          #     description: <string>
          #     ext_intf: <list or string>
          #     extip: <string>
          #     extport: <string>
          #     id: <integer>
          #     intl_intf: <list or string>
          #     mapping_filter_limit: <integer>
          #     maximal_lifetime: <integer>
          #     minimal_lifetime: <integer>
          #     multicast_announcement: <value in [disable, enable]>
          #     name: <string>
          #     recycle_delay: <integer>
          #     third_party: <value in [disallow, allow]>
          #     third_party_subnet: <list or string>
          # status: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/system/pcp-server'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'system_pcpserver': {
            'type': 'dict',
            'v_range': [['7.4.3', '']],
            'options': {
                'pools': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'allow-opcode': {'v_range': [['7.4.3', '']], 'type': 'list', 'choices': ['map', 'peer', 'announce'], 'elements': 'str'},
                        'announcement-count': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'arp-reply': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'client-mapping-limit': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'client-subnet': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'description': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'ext-intf': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'extip': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'extport': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'intl-intf': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'mapping-filter-limit': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'maximal-lifetime': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'minimal-lifetime': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'multicast-announcement': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                        'recycle-delay': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'third-party': {'v_range': [['7.4.3', '']], 'choices': ['disallow', 'allow'], 'type': 'str'},
                        'third-party-subnet': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_pcpserver'),
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
