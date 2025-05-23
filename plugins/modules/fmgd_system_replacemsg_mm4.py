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
module: fmgd_system_replacemsg_mm4
short_description: Replacement messages.
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
    system_replacemsg_mm4:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            add_smil:
                aliases: ['add-smil']
                type: str
                description: Add message encapsulation
                choices:
                    - 'disable'
                    - 'enable'
            charset:
                type: str
                description: Character encoding used for replacement message
                choices:
                    - 'us-ascii'
                    - 'utf-8'
            class:
                type: str
                description: Message class
                choices:
                    - 'personal'
                    - 'advertisement'
                    - 'informational'
                    - 'auto'
                    - 'not-included'
            domain:
                type: str
                description: From address domain
            format:
                type: str
                description: Format flag.
                choices:
                    - 'none'
                    - 'text'
                    - 'html'
                    - 'wml'
            from:
                type: str
                description: From address
            from_sender:
                aliases: ['from-sender']
                type: str
                description: Notification message sent from recipient
                choices:
                    - 'disable'
                    - 'enable'
            header:
                type: str
                description: Header flag.
                choices:
                    - 'none'
                    - 'http'
                    - '8bit'
            image:
                type: list
                elements: str
                description: Message string.
            fmgr_message:
                type: str
                description: Message text
            msg_type:
                aliases: ['msg-type']
                type: str
                description: Message type.
            priority:
                type: str
                description: Message priority
                choices:
                    - 'low'
                    - 'normal'
                    - 'high'
                    - 'not-included'
            rsp_status:
                aliases: ['rsp-status']
                type: str
                description: Response status
                choices:
                    - 'ok'
                    - 'err-unspecified'
                    - 'err-srv-denied'
                    - 'err-msg-fmt-corrupt'
                    - 'err-snd-addr-unresolv'
                    - 'err-net-prob'
                    - 'err-content-not-accept'
                    - 'err-unsupp-msg'
            smil_part:
                aliases: ['smil-part']
                type: str
                description: Message encapsulation text
            subject:
                type: str
                description: Subject text string
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
    - name: Replacement messages.
      fortinet.fmgdevice.fmgd_system_replacemsg_mm4:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_replacemsg_mm4:
          # add_smil: <value in [disable, enable]>
          # charset: <value in [us-ascii, utf-8]>
          # class: <value in [personal, advertisement, informational, ...]>
          # domain: <string>
          # format: <value in [none, text, html, ...]>
          # from: <string>
          # from_sender: <value in [disable, enable]>
          # header: <value in [none, http, 8bit]>
          # image: <list or string>
          # fmgr_message: <string>
          # msg_type: <string>
          # priority: <value in [low, normal, high, ...]>
          # rsp_status: <value in [ok, err-unspecified, err-srv-denied, ...]>
          # smil_part: <string>
          # subject: <string>
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
        '/pm/config/device/{device}/global/system/replacemsg/mm4'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_replacemsg_mm4': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'add-smil': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'charset': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['us-ascii', 'utf-8'], 'type': 'str'},
                'class': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['personal', 'advertisement', 'informational', 'auto', 'not-included'],
                    'type': 'str'
                },
                'domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'format': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'text', 'html', 'wml'], 'type': 'str'},
                'from': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'from-sender': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'header': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'http', '8bit'], 'type': 'str'},
                'image': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fmgr_message': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'msg-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'priority': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['low', 'normal', 'high', 'not-included'], 'type': 'str'},
                'rsp-status': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'ok', 'err-unspecified', 'err-srv-denied', 'err-msg-fmt-corrupt', 'err-snd-addr-unresolv', 'err-net-prob',
                        'err-content-not-accept', 'err-unsupp-msg'
                    ],
                    'type': 'str'
                },
                'smil-part': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'subject': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_replacemsg_mm4'),
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
