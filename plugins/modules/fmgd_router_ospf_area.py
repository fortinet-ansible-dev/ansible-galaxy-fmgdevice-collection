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
module: fmgd_router_ospf_area
short_description: OSPF area configuration.
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
    router_ospf_area:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            authentication:
                type: str
                description: Authentication type.
                choices:
                    - 'none'
                    - 'text'
                    - 'md5'
                    - 'message-digest'
            comments:
                type: str
                description: Comment.
            default_cost:
                aliases: ['default-cost']
                type: int
                description: Summary default cost of stub or NSSA area.
            filter_list:
                aliases: ['filter-list']
                type: list
                elements: dict
                description: Filter list.
                suboptions:
                    direction:
                        type: str
                        description: Direction.
                        choices:
                            - 'out'
                            - 'in'
                    id:
                        type: int
                        description: Filter list entry ID.
                    list:
                        type: list
                        elements: str
                        description: Access-list or prefix-list name.
            id:
                type: str
                description: Area entry IP address.
                required: true
            nssa_default_information_originate:
                aliases: ['nssa-default-information-originate']
                type: str
                description: Redistribute, advertise, or do not originate Type-7 default route into NSSA area.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'always'
            nssa_default_information_originate_metric:
                aliases: ['nssa-default-information-originate-metric']
                type: int
                description: OSPF default metric.
            nssa_default_information_originate_metric_type:
                aliases: ['nssa-default-information-originate-metric-type']
                type: str
                description: OSPF metric type for default routes.
                choices:
                    - '2'
                    - '1'
            nssa_redistribution:
                aliases: ['nssa-redistribution']
                type: str
                description: Enable/disable redistribute into NSSA area.
                choices:
                    - 'disable'
                    - 'enable'
            nssa_translator_role:
                aliases: ['nssa-translator-role']
                type: str
                description: NSSA translator role type.
                choices:
                    - 'candidate'
                    - 'never'
                    - 'always'
            range:
                type: list
                elements: dict
                description: Range.
                suboptions:
                    advertise:
                        type: str
                        description: Enable/disable advertise status.
                        choices:
                            - 'disable'
                            - 'enable'
                    id:
                        type: int
                        description: Range entry ID.
                    prefix:
                        type: list
                        elements: str
                        description: Prefix.
                    substitute:
                        type: list
                        elements: str
                        description: Substitute prefix.
                    substitute_status:
                        aliases: ['substitute-status']
                        type: str
                        description: Enable/disable substitute status.
                        choices:
                            - 'disable'
                            - 'enable'
            shortcut:
                type: str
                description: Enable/disable shortcut option.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'default'
            stub_type:
                aliases: ['stub-type']
                type: str
                description: Stub summary setting.
                choices:
                    - 'summary'
                    - 'no-summary'
            type:
                type: str
                description: Area type setting.
                choices:
                    - 'regular'
                    - 'nssa'
                    - 'stub'
            virtual_link:
                aliases: ['virtual-link']
                type: list
                elements: dict
                description: Virtual link.
                suboptions:
                    authentication:
                        type: str
                        description: Authentication type.
                        choices:
                            - 'none'
                            - 'text'
                            - 'md5'
                            - 'message-digest'
                    authentication_key:
                        aliases: ['authentication-key']
                        type: list
                        elements: str
                        description: Authentication key.
                    dead_interval:
                        aliases: ['dead-interval']
                        type: int
                        description: Dead interval.
                    hello_interval:
                        aliases: ['hello-interval']
                        type: int
                        description: Hello interval.
                    keychain:
                        type: list
                        elements: str
                        description: Message-digest key-chain name.
                    md5_keys:
                        aliases: ['md5-keys']
                        type: list
                        elements: dict
                        description: Md5 keys.
                        suboptions:
                            id:
                                type: int
                                description: Key ID
                            key_string:
                                aliases: ['key-string']
                                type: list
                                elements: str
                                description: Password for the key.
                    name:
                        type: str
                        description: Virtual link entry name.
                    peer:
                        type: str
                        description: Peer IP.
                    retransmit_interval:
                        aliases: ['retransmit-interval']
                        type: int
                        description: Retransmit interval.
                    transmit_delay:
                        aliases: ['transmit-delay']
                        type: int
                        description: Transmit delay.
                    md5_keychain:
                        aliases: ['md5-keychain']
                        type: list
                        elements: str
                        description: Authentication MD5 key-chain name.
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
    - name: OSPF area configuration.
      fortinet.fmgdevice.fmgd_router_ospf_area:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        router_ospf_area:
          id: "your value" # Required variable, string
          # authentication: <value in [none, text, md5, ...]>
          # comments: <string>
          # default_cost: <integer>
          # filter_list:
          #   - direction: <value in [out, in]>
          #     id: <integer>
          #     list: <list or string>
          # nssa_default_information_originate: <value in [disable, enable, always]>
          # nssa_default_information_originate_metric: <integer>
          # nssa_default_information_originate_metric_type: <value in [2, 1]>
          # nssa_redistribution: <value in [disable, enable]>
          # nssa_translator_role: <value in [candidate, never, always]>
          # range:
          #   - advertise: <value in [disable, enable]>
          #     id: <integer>
          #     prefix: <list or string>
          #     substitute: <list or string>
          #     substitute_status: <value in [disable, enable]>
          # shortcut: <value in [disable, enable, default]>
          # stub_type: <value in [summary, no-summary]>
          # type: <value in [regular, nssa, stub]>
          # virtual_link:
          #   - authentication: <value in [none, text, md5, ...]>
          #     authentication_key: <list or string>
          #     dead_interval: <integer>
          #     hello_interval: <integer>
          #     keychain: <list or string>
          #     md5_keys:
          #       - id: <integer>
          #         key_string: <list or string>
          #     name: <string>
          #     peer: <string>
          #     retransmit_interval: <integer>
          #     transmit_delay: <integer>
          #     md5_keychain: <list or string>
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
        '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'router_ospf_area': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'authentication': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'text', 'md5', 'message-digest'], 'type': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'default-cost': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'filter-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['out', 'in'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'nssa-default-information-originate': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'always'],
                    'type': 'str'
                },
                'nssa-default-information-originate-metric': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'nssa-default-information-originate-metric-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['2', '1'], 'type': 'str'},
                'nssa-redistribution': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nssa-translator-role': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['candidate', 'never', 'always'], 'type': 'str'},
                'range': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'advertise': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'prefix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'substitute': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'substitute-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'shortcut': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'default'], 'type': 'str'},
                'stub-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['summary', 'no-summary'], 'type': 'str'},
                'type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['regular', 'nssa', 'stub'], 'type': 'str'},
                'virtual-link': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'authentication': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': ['none', 'text', 'md5', 'message-digest'],
                            'type': 'str'
                        },
                        'authentication-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'dead-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'hello-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'md5-keys': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'no_log': True,
                            'type': 'list',
                            'options': {
                                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                                'key-string': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'peer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'retransmit-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'transmit-delay': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'md5-keychain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'}
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'router_ospf_area'),
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
