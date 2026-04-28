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
module: fmgd_firewall_address6
short_description: Configure IPv6 firewall addresses.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
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
    firewall_address6:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _image_base64:
                aliases: ['_image-base64']
                type: str
                description: Image base64.
            cache_ttl:
                aliases: ['cache-ttl']
                type: int
                description: Minimal TTL of individual IPv6 addresses in FQDN cache.
            color:
                type: int
                description: Integer value to determine the color of the icon in the GUI
            comment:
                type: str
                description: Comment.
            country:
                type: list
                elements: str
                description: IPv6 addresses associated to a specific country.
            dynamic_mapping:
                type: list
                elements: dict
                description: Dynamic mapping.
                suboptions:
                    _image_base64:
                        aliases: ['_image-base64']
                        type: str
                        description: Image base64.
                    _scope:
                        type: list
                        elements: dict
                        description: Scope.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            vdom:
                                type: str
                                description: Vdom.
                    cache_ttl:
                        aliases: ['cache-ttl']
                        type: int
                        description: Minimal TTL of individual IPv6 addresses in FQDN cache.
                    color:
                        type: int
                        description: Integer value to determine the color of the icon in the GUI
                    comment:
                        type: str
                        description: Comment.
                    country:
                        type: list
                        elements: str
                        description: IPv6 addresses associated to a specific country.
                    end_ip:
                        aliases: ['end-ip']
                        type: str
                        description:
                            - Support meta variable
                            - Final IP address
                    end_mac:
                        aliases: ['end-mac']
                        type: str
                        description: Support meta variable
                    epg_name:
                        aliases: ['epg-name']
                        type: str
                        description: Endpoint group name.
                    fabric_object:
                        aliases: ['fabric-object']
                        type: str
                        description: Security Fabric global object setting.
                        choices:
                            - 'disable'
                            - 'enable'
                    filter:
                        type: str
                        description: Match criteria filter.
                    fqdn:
                        type: str
                        description:
                            - Support meta variable
                            - Fully qualified domain name.
                    global_object:
                        aliases: ['global-object']
                        type: int
                        description: Global object.
                    host:
                        type: str
                        description: Host Address.
                    host_type:
                        aliases: ['host-type']
                        type: str
                        description: Host type.
                        choices:
                            - 'any'
                            - 'specific'
                    ip6:
                        type: str
                        description:
                            - Support meta variable
                            - IPv6 address prefix
                    macaddr:
                        type: list
                        elements: str
                        description:
                            - Support meta variable
                            - Multiple MAC address ranges.
                    obj_id:
                        aliases: ['obj-id']
                        type: str
                        description: Object ID for NSX.
                    route_tag:
                        aliases: ['route-tag']
                        type: int
                        description: Route-tag address.
                    sdn:
                        type: list
                        elements: str
                        description: SDN.
                    sdn_addr_type:
                        aliases: ['sdn-addr-type']
                        type: str
                        description: Type of addresses to collect.
                        choices:
                            - 'all'
                            - 'private'
                            - 'public'
                    sdn_tag:
                        aliases: ['sdn-tag']
                        type: str
                        description: SDN Tag.
                    start_ip:
                        aliases: ['start-ip']
                        type: str
                        description:
                            - Support meta variable
                            - First IP address
                    start_mac:
                        aliases: ['start-mac']
                        type: str
                        description: Support meta variable
                    subnet_segment:
                        aliases: ['subnet-segment']
                        type: list
                        elements: dict
                        description: Subnet segment.
                        suboptions:
                            name:
                                type: str
                                description: Name.
                            type:
                                type: str
                                description: Subnet segment type.
                                choices:
                                    - 'any'
                                    - 'specific'
                            value:
                                type: str
                                description: Subnet segment value.
                    tags:
                        type: list
                        elements: str
                        description: Names of object-tags applied to address.
                    template:
                        type: list
                        elements: str
                        description: IPv6 address template.
                    tenant:
                        type: str
                        description: Tenant.
                    type:
                        type: str
                        description: Type of IPv6 address object
                        choices:
                            - 'ipprefix'
                            - 'iprange'
                            - 'dynamic'
                            - 'fqdn'
                            - 'template'
                            - 'geography'
                            - 'route-tag'
                            - 'mac'
                            - 'wildcard'
                    uuid:
                        type: str
                        description: Universally Unique Identifier
                    visibility:
                        type: str
                        description: Enable/disable the visibility of the object in the GUI.
                        choices:
                            - 'disable'
                            - 'enable'
                    wildcard:
                        type: str
                        description: IPv6 address and wildcard netmask.
                    passive_fqdn_learning:
                        aliases: ['passive-fqdn-learning']
                        type: str
                        description: Enable/disable passive learning of FQDNs.
                        choices:
                            - 'disable'
                            - 'enable'
            end_ip:
                aliases: ['end-ip']
                type: str
                description:
                    - Support meta variable
                    - Final IP address
            epg_name:
                aliases: ['epg-name']
                type: str
                description: Endpoint group name.
            fabric_object:
                aliases: ['fabric-object']
                type: str
                description: Security Fabric global object setting.
                choices:
                    - 'disable'
                    - 'enable'
            fqdn:
                type: str
                description:
                    - Support meta variable
                    - Fully qualified domain name.
            host:
                type: str
                description: Host Address.
            host_type:
                aliases: ['host-type']
                type: str
                description: Host type.
                choices:
                    - 'any'
                    - 'specific'
            ip6:
                type: str
                description:
                    - Support meta variable
                    - IPv6 address prefix
            list:
                type: list
                elements: dict
                description: List.
                suboptions:
                    ip:
                        type: str
                        description: IP.
                    net_id:
                        aliases: ['net-id']
                        type: str
                        description: Network ID.
                    obj_id:
                        aliases: ['obj-id']
                        type: str
                        description: Object ID.
            name:
                type: str
                description: Address name.
                required: true
            obj_id:
                aliases: ['obj-id']
                type: str
                description: Object ID for NSX.
            sdn:
                type: list
                elements: str
                description: SDN.
            sdn_tag:
                aliases: ['sdn-tag']
                type: str
                description: SDN Tag.
            start_ip:
                aliases: ['start-ip']
                type: str
                description:
                    - Support meta variable
                    - First IP address
            subnet_segment:
                aliases: ['subnet-segment']
                type: list
                elements: dict
                description: Subnet segment.
                suboptions:
                    name:
                        type: str
                        description: Name.
                    type:
                        type: str
                        description: Subnet segment type.
                        choices:
                            - 'any'
                            - 'specific'
                    value:
                        type: str
                        description: Subnet segment value.
            tagging:
                type: list
                elements: dict
                description: Tagging.
                suboptions:
                    category:
                        type: list
                        elements: str
                        description: Tag category.
                    name:
                        type: str
                        description: Tagging entry name.
                    tags:
                        type: list
                        elements: str
                        description: Tags.
            template:
                type: list
                elements: str
                description: IPv6 address template.
            tenant:
                type: str
                description: Tenant.
            type:
                type: str
                description: Type of IPv6 address object
                choices:
                    - 'ipprefix'
                    - 'iprange'
                    - 'dynamic'
                    - 'fqdn'
                    - 'template'
                    - 'geography'
                    - 'route-tag'
                    - 'mac'
                    - 'wildcard'
            uuid:
                type: str
                description: Universally Unique Identifier
            filter:
                type: str
                description: Match criteria filter.
            route_tag:
                aliases: ['route-tag']
                type: int
                description: Route-tag address.
            macaddr:
                type: list
                elements: str
                description:
                    - Support meta variable
                    - Multiple MAC address ranges.
            sdn_addr_type:
                aliases: ['sdn-addr-type']
                type: str
                description: Type of addresses to collect.
                choices:
                    - 'all'
                    - 'private'
                    - 'public'
            tags:
                type: list
                elements: str
                description: Names of object-tags applied to address.
            global_object:
                aliases: ['global-object']
                type: int
                description: Global object.
            start_mac:
                aliases: ['start-mac']
                type: str
                description:
                    - Support meta variable
                    - First MAC address in the range.
            end_mac:
                aliases: ['end-mac']
                type: str
                description:
                    - Support meta variable
                    - Last MAC address in the range.
            visibility:
                type: str
                description: Enable/disable the visibility of the object in the GUI.
                choices:
                    - 'disable'
                    - 'enable'
            wildcard:
                type: str
                description: IPv6 address and wildcard netmask.
            passive_fqdn_learning:
                aliases: ['passive-fqdn-learning']
                type: str
                description: Enable/disable passive learning of FQDNs.
                choices:
                    - 'disable'
                    - 'enable'
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure IPv6 firewall addresses.
      fortinet.fmgdevice.fmgd_firewall_address6:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_address6:
          name: "your value" # Required variable, string
          # _image_base64: <string>
          # cache_ttl: <integer>
          # color: <integer>
          # comment: <string>
          # country: <list or string>
          # dynamic_mapping:
          #   - _image_base64: <string>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     cache_ttl: <integer>
          #     color: <integer>
          #     comment: <string>
          #     country: <list or string>
          #     end_ip: <string>
          #     end_mac: <string>
          #     epg_name: <string>
          #     fabric_object: <value in [disable, enable]>
          #     filter: <string>
          #     fqdn: <string>
          #     global_object: <integer>
          #     host: <string>
          #     host_type: <value in [any, specific]>
          #     ip6: <string>
          #     macaddr: <list or string>
          #     obj_id: <string>
          #     route_tag: <integer>
          #     sdn: <list or string>
          #     sdn_addr_type: <value in [all, private, public]>
          #     sdn_tag: <string>
          #     start_ip: <string>
          #     start_mac: <string>
          #     subnet_segment:
          #       - name: <string>
          #         type: <value in [any, specific]>
          #         value: <string>
          #     tags: <list or string>
          #     template: <list or string>
          #     tenant: <string>
          #     type: <value in [ipprefix, iprange, dynamic, ...]>
          #     uuid: <string>
          #     visibility: <value in [disable, enable]>
          #     wildcard: <string>
          #     passive_fqdn_learning: <value in [disable, enable]>
          # end_ip: <string>
          # epg_name: <string>
          # fabric_object: <value in [disable, enable]>
          # fqdn: <string>
          # host: <string>
          # host_type: <value in [any, specific]>
          # ip6: <string>
          # list:
          #   - ip: <string>
          #     net_id: <string>
          #     obj_id: <string>
          # obj_id: <string>
          # sdn: <list or string>
          # sdn_tag: <string>
          # start_ip: <string>
          # subnet_segment:
          #   - name: <string>
          #     type: <value in [any, specific]>
          #     value: <string>
          # tagging:
          #   - category: <list or string>
          #     name: <string>
          #     tags: <list or string>
          # template: <list or string>
          # tenant: <string>
          # type: <value in [ipprefix, iprange, dynamic, ...]>
          # uuid: <string>
          # filter: <string>
          # route_tag: <integer>
          # macaddr: <list or string>
          # sdn_addr_type: <value in [all, private, public]>
          # tags: <list or string>
          # global_object: <integer>
          # start_mac: <string>
          # end_mac: <string>
          # visibility: <value in [disable, enable]>
          # wildcard: <string>
          # passive_fqdn_learning: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/address6'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_address6': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                '_image-base64': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'cache-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'color': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'country': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_image-base64': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'cache-ttl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'color': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'country': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'end-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'end-mac': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'epg-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'fabric-object': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'filter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'fqdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'global-object': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'host': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'host-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['any', 'specific'], 'type': 'str'},
                        'ip6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'macaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'obj-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'route-tag': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'sdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'sdn-addr-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['all', 'private', 'public'], 'type': 'str'},
                        'sdn-tag': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'start-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'start-mac': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'subnet-segment': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['any', 'specific'], 'type': 'str'},
                                'value': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'tags': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'template': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'tenant': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'type': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'choices': ['ipprefix', 'iprange', 'dynamic', 'fqdn', 'template', 'geography', 'route-tag', 'mac', 'wildcard'],
                            'type': 'str'
                        },
                        'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'visibility': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wildcard': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'passive-fqdn-learning': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'end-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'epg-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'fabric-object': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fqdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'host': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'host-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['any', 'specific'], 'type': 'str'},
                'ip6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'net-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'obj-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'obj-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'sdn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sdn-tag': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'start-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'subnet-segment': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['any', 'specific'], 'type': 'str'},
                        'value': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'tagging': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'tags': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'template': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'tenant': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'type': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['ipprefix', 'iprange', 'dynamic', 'fqdn', 'template', 'geography', 'route-tag', 'mac', 'wildcard'],
                    'type': 'str'
                },
                'uuid': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'filter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'route-tag': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'macaddr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sdn-addr-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['all', 'private', 'public'], 'type': 'str'},
                'tags': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'global-object': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'start-mac': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'end-mac': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'visibility': {'v_range': [['7.4.8', '7.4.10']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'wildcard': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'passive-fqdn-learning': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address6'),
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
