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
module: fmgd_webfilter_urlfilter
short_description: Configure URL filter lists.
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
    webfilter_urlfilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Optional comments.
            entries:
                type: list
                elements: dict
                description: Entries.
                suboptions:
                    action:
                        type: str
                        description: Action to take for URL filter matches.
                        choices:
                            - 'exempt'
                            - 'block'
                            - 'allow'
                            - 'monitor'
                    antiphish_action:
                        aliases: ['antiphish-action']
                        type: str
                        description: Action to take for AntiPhishing matches.
                        choices:
                            - 'block'
                            - 'log'
                    dns_address_family:
                        aliases: ['dns-address-family']
                        type: str
                        description: Resolve IPv4 address, IPv6 address, or both from DNS server.
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                            - 'both'
                    exempt:
                        type: list
                        elements: str
                        description: If action is set to exempt, select the security profile operations that exempt URLs skip.
                        choices:
                            - 'av'
                            - 'web-content'
                            - 'activex-java-cookie'
                            - 'dlp'
                            - 'fortiguard'
                            - 'all'
                            - 'pass'
                            - 'range-block'
                            - 'antiphish'
                    id:
                        type: int
                        description: Id.
                    referrer_host:
                        aliases: ['referrer-host']
                        type: str
                        description: Referrer host name.
                    status:
                        type: str
                        description: Enable/disable this URL filter.
                        choices:
                            - 'disable'
                            - 'enable'
                    type:
                        type: str
                        description: Filter type
                        choices:
                            - 'simple'
                            - 'regex'
                            - 'wildcard'
                    url:
                        type: str
                        description: URL to be filtered.
                    web_proxy_profile:
                        aliases: ['web-proxy-profile']
                        type: list
                        elements: str
                        description: Web proxy profile.
                    comment:
                        type: str
                        description: Comment.
            id:
                type: int
                description: ID.
                required: true
            include_subdomains:
                aliases: ['include-subdomains']
                type: str
                description: Include subdomains.
                choices:
                    - 'disable'
                    - 'enable'
            ip_addr_block:
                aliases: ['ip-addr-block']
                type: str
                description: Enable/disable blocking URLs when the hostname appears as an IP address.
                choices:
                    - 'disable'
                    - 'enable'
            ip4_mapped_ip6:
                aliases: ['ip4-mapped-ip6']
                type: str
                description: Enable/disable matching of IPv4 mapped IPv6 URLs.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name of URL filter list.
            one_arm_ips_urlfilter:
                aliases: ['one-arm-ips-urlfilter']
                type: str
                description: Enable/disable DNS resolver for one-arm IPS URL filter operation.
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
    - name: Configure URL filter lists.
      fortinet.fmgdevice.fmgd_webfilter_urlfilter:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        webfilter_urlfilter:
          id: 0 # Required variable, integer
          # comment: <string>
          # entries:
          #   - action: <value in [exempt, block, allow, ...]>
          #     antiphish_action: <value in [block, log]>
          #     dns_address_family: <value in [ipv4, ipv6, both]>
          #     exempt:
          #       - "av"
          #       - "web-content"
          #       - "activex-java-cookie"
          #       - "dlp"
          #       - "fortiguard"
          #       - "all"
          #       - "pass"
          #       - "range-block"
          #       - "antiphish"
          #     id: <integer>
          #     referrer_host: <string>
          #     status: <value in [disable, enable]>
          #     type: <value in [simple, regex, wildcard]>
          #     url: <string>
          #     web_proxy_profile: <list or string>
          #     comment: <string>
          # include_subdomains: <value in [disable, enable]>
          # ip_addr_block: <value in [disable, enable]>
          # ip4_mapped_ip6: <value in [disable, enable]>
          # name: <string>
          # one_arm_ips_urlfilter: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/webfilter/urlfilter'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'webfilter_urlfilter': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'comment': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'entries': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['exempt', 'block', 'allow', 'monitor'], 'type': 'str'},
                        'antiphish-action': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['block', 'log'], 'type': 'str'},
                        'dns-address-family': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['ipv4', 'ipv6', 'both'], 'type': 'str'},
                        'exempt': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['av', 'web-content', 'activex-java-cookie', 'dlp', 'fortiguard', 'all', 'pass', 'range-block', 'antiphish'],
                            'elements': 'str'
                        },
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                        'referrer-host': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['simple', 'regex', 'wildcard'], 'type': 'str'},
                        'url': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'web-proxy-profile': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'comment': {'v_range': [['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'int'},
                'include-subdomains': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-addr-block': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip4-mapped-ip6': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'one-arm-ips-urlfilter': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'webfilter_urlfilter'),
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
