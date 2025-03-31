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
module: fmgd_antivirus_quarantine
short_description: Configure quarantine options.
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
    antivirus_quarantine:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            agelimit:
                type: int
                description: Age limit for quarantined files
            destination:
                type: str
                description: Choose whether to quarantine files to the FortiGate disk or to FortiAnalyzer or to delete them instead of quarantining them.
                choices:
                    - 'NULL'
                    - 'disk'
                    - 'FortiAnalyzer'
            drop_infected:
                aliases: ['drop-infected']
                type: list
                elements: str
                description: Do not quarantine infected files found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'im'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            drop_machine_learning:
                aliases: ['drop-machine-learning']
                type: list
                elements: str
                description: Do not quarantine files detected by machine learning found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            lowspace:
                type: str
                description: Select the method for handling additional files when running low on disk space.
                choices:
                    - 'ovrw-old'
                    - 'drop-new'
            maxfilesize:
                type: int
                description: Maximum file size to quarantine
            quarantine_quota:
                aliases: ['quarantine-quota']
                type: int
                description: The amount of disk space to reserve for quarantining files
            store_infected:
                aliases: ['store-infected']
                type: list
                elements: str
                description: Quarantine infected files found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'im'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            store_machine_learning:
                aliases: ['store-machine-learning']
                type: list
                elements: str
                description: Quarantine files detected by machine learning found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            drop_blocked:
                aliases: ['drop-blocked']
                type: list
                elements: str
                description: Do not quarantine dropped files found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            store_blocked:
                aliases: ['store-blocked']
                type: list
                elements: str
                description: Quarantine blocked files found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            drop_heuristic:
                aliases: ['drop-heuristic']
                type: list
                elements: str
                description: Do not quarantine files detected by heuristics found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'im'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            store_heuristic:
                aliases: ['store-heuristic']
                type: list
                elements: str
                description: Quarantine files detected by heuristics found in sessions using the selected protocols.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'im'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
                    - 'cifs'
                    - 'ssh'
            drop_intercepted:
                aliases: ['drop-intercepted']
                type: list
                elements: str
                description: Drop intercepted from a protocol
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
            store_intercepted:
                aliases: ['store-intercepted']
                type: list
                elements: str
                description: Quarantine intercepted from a protocol
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
                    - 'ftps'
                    - 'mapi'
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
    - name: Configure quarantine options.
      fortinet.fmgdevice.fmgd_antivirus_quarantine:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        antivirus_quarantine:
          # agelimit: <integer>
          # destination: <value in [NULL, disk, FortiAnalyzer]>
          # drop_infected:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "im"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # drop_machine_learning:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # lowspace: <value in [ovrw-old, drop-new]>
          # maxfilesize: <integer>
          # quarantine_quota: <integer>
          # store_infected:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "im"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # store_machine_learning:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # drop_blocked:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # store_blocked:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # drop_heuristic:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "im"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # store_heuristic:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "im"
          #   - "nntp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          #   - "cifs"
          #   - "ssh"
          # drop_intercepted:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
          # store_intercepted:
          #   - "imap"
          #   - "smtp"
          #   - "pop3"
          #   - "http"
          #   - "ftp"
          #   - "imaps"
          #   - "smtps"
          #   - "pop3s"
          #   - "https"
          #   - "mm1"
          #   - "mm3"
          #   - "mm4"
          #   - "mm7"
          #   - "ftps"
          #   - "mapi"
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
        '/pm/config/device/{device}/vdom/{vdom}/antivirus/quarantine'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'antivirus_quarantine': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'agelimit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'destination': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['NULL', 'disk', 'FortiAnalyzer'], 'type': 'str'},
                'drop-infected': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'http', 'ftp', 'im', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps',
                        'mapi', 'cifs', 'ssh'
                    ],
                    'elements': 'str'
                },
                'drop-machine-learning': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'http', 'ftp', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'ftps', 'mapi', 'cifs', 'ssh'],
                    'elements': 'str'
                },
                'lowspace': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ovrw-old', 'drop-new'], 'type': 'str'},
                'maxfilesize': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'quarantine-quota': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'store-infected': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'http', 'ftp', 'im', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps',
                        'mapi', 'cifs', 'ssh'
                    ],
                    'elements': 'str'
                },
                'store-machine-learning': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'http', 'ftp', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'ftps', 'mapi', 'cifs', 'ssh'],
                    'elements': 'str'
                },
                'drop-blocked': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'http', 'ftp', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps', 'mapi',
                        'cifs', 'ssh'
                    ],
                    'elements': 'str'
                },
                'store-blocked': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'http', 'ftp', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps', 'mapi',
                        'cifs', 'ssh'
                    ],
                    'elements': 'str'
                },
                'drop-heuristic': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'http', 'ftp', 'im', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps',
                        'mapi', 'cifs', 'ssh'
                    ],
                    'elements': 'str'
                },
                'store-heuristic': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'imap', 'smtp', 'pop3', 'http', 'ftp', 'im', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps',
                        'mapi', 'cifs', 'ssh'
                    ],
                    'elements': 'str'
                },
                'drop-intercepted': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'http', 'ftp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps', 'mapi'],
                    'elements': 'str'
                },
                'store-intercepted': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'http', 'ftp', 'imaps', 'smtps', 'pop3s', 'https', 'mm1', 'mm3', 'mm4', 'mm7', 'ftps', 'mapi'],
                    'elements': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_quarantine'),
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
