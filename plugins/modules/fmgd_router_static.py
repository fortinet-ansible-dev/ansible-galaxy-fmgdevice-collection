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
module: fmgd_router_static
short_description: Configure IPv4 static routing tables.
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
    router_static:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bfd:
                type: str
                description: Enable/disable Bidirectional Forwarding Detection
                choices:
                    - 'disable'
                    - 'enable'
            blackhole:
                type: str
                description: Enable/disable black hole.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Optional comments.
            device:
                type: list
                elements: str
                description: Gateway out interface or tunnel.
            distance:
                type: int
                description: Administrative distance
            dst:
                type: list
                elements: str
                description: Destination IP and mask for this route.
            dstaddr:
                type: list
                elements: str
                description: Name of firewall address or address group.
            dynamic_gateway:
                aliases: ['dynamic-gateway']
                type: str
                description: Enable use of dynamic gateway retrieved from a DHCP or PPP server.
                choices:
                    - 'disable'
                    - 'enable'
            gateway:
                type: str
                description: Gateway IP for this route.
            internet_service:
                aliases: ['internet-service']
                type: list
                elements: str
                description: Application ID in the Internet service database.
            internet_service_custom:
                aliases: ['internet-service-custom']
                type: list
                elements: str
                description: Application name in the Internet service custom database.
            link_monitor_exempt:
                aliases: ['link-monitor-exempt']
                type: str
                description: Enable/disable withdrawal of this static route when link monitor or health check is down.
                choices:
                    - 'disable'
                    - 'enable'
            preferred_source:
                aliases: ['preferred-source']
                type: str
                description: Preferred source IP for this route.
            priority:
                type: int
                description: Administrative priority
            sdwan_zone:
                aliases: ['sdwan-zone']
                type: list
                elements: str
                description: Choose SD-WAN Zone.
            seq_num:
                aliases: ['seq-num']
                type: int
                description: Sequence number.
            src:
                type: list
                elements: str
                description: Source prefix for this route.
            status:
                type: str
                description: Enable/disable this static route.
                choices:
                    - 'disable'
                    - 'enable'
            tag:
                type: int
                description: Route tag.
            vrf:
                type: str
                description: Virtual Routing Forwarding ID.
            weight:
                type: int
                description: Administrative weight
            sdwan:
                type: str
                description: Enable/disable egress through SD-WAN.
                choices:
                    - 'disable'
                    - 'enable'
            dst_type:
                aliases: ['dst-type']
                type: str
                description: Dst type.
                choices:
                    - 'ipmask'
                    - 'addrname'
                    - 'service-id'
                    - 'service-custom'
            virtual_wan_link:
                aliases: ['virtual-wan-link']
                type: str
                description: Enable/disable egress through the virtual-wan-link.
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
    - name: Configure IPv4 static routing tables.
      fortinet.fmgdevice.fmgd_router_static:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_static:
          seq_num: 0 # Required variable, integer
          # bfd: <value in [disable, enable]>
          # blackhole: <value in [disable, enable]>
          # comment: <string>
          # device: <list or string>
          # distance: <integer>
          # dst: <list or string>
          # dstaddr: <list or string>
          # dynamic_gateway: <value in [disable, enable]>
          # gateway: <string>
          # internet_service: <list or string>
          # internet_service_custom: <list or string>
          # link_monitor_exempt: <value in [disable, enable]>
          # preferred_source: <string>
          # priority: <integer>
          # sdwan_zone: <list or string>
          # src: <list or string>
          # status: <value in [disable, enable]>
          # tag: <integer>
          # vrf: <string>
          # weight: <integer>
          # sdwan: <value in [disable, enable]>
          # dst_type: <value in [ipmask, addrname, service-id, ...]>
          # virtual_wan_link: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/static'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'seq_num'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_static': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'bfd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'blackhole': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'device': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'distance': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'dst': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dstaddr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dynamic-gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'gateway': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'internet-service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'internet-service-custom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'link-monitor-exempt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'preferred-source': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sdwan-zone': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'seq-num': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'src': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tag': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'vrf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'sdwan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dst-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['ipmask', 'addrname', 'service-id', 'service-custom'],
                    'type': 'str'
                },
                'virtual-wan-link': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_static'),
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
