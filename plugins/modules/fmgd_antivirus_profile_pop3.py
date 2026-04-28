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
module: fmgd_antivirus_profile_pop3
short_description: Configure POP3 AntiVirus options.
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
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    antivirus_profile_pop3:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            archive_block:
                aliases: ['archive-block']
                type: list
                elements: str
                description: Select the archive types to block.
                choices:
                    - 'encrypted'
                    - 'corrupted'
                    - 'multipart'
                    - 'nested'
                    - 'mailbomb'
                    - 'unhandled'
                    - 'partiallycorrupted'
                    - 'timeout'
                    - 'fileslimit'
            archive_log:
                aliases: ['archive-log']
                type: list
                elements: str
                description: Select the archive types to log.
                choices:
                    - 'encrypted'
                    - 'corrupted'
                    - 'multipart'
                    - 'nested'
                    - 'mailbomb'
                    - 'unhandled'
                    - 'partiallycorrupted'
                    - 'timeout'
                    - 'fileslimit'
            av_scan:
                aliases: ['av-scan']
                type: str
                description: Enable AntiVirus scan service.
                choices:
                    - 'disable'
                    - 'monitor'
                    - 'block'
            content_disarm:
                aliases: ['content-disarm']
                type: str
                description: Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
                choices:
                    - 'disable'
                    - 'enable'
            emulator:
                type: str
                description: Enable/disable the virus emulator.
                choices:
                    - 'disable'
                    - 'enable'
            executables:
                type: str
                description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                choices:
                    - 'default'
                    - 'virus'
            external_blocklist:
                aliases: ['external-blocklist']
                type: str
                description: Enable external-blocklist.
                choices:
                    - 'disable'
                    - 'monitor'
                    - 'block'
            fortindr:
                type: str
                description: Enable scanning of files by FortiNDR.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            fortisandbox:
                type: str
                description: Enable scanning of files by FortiSandbox.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            outbreak_prevention:
                aliases: ['outbreak-prevention']
                type: str
                description: Enable virus outbreak prevention service.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
                    - 'files'
                    - 'disabled'
                    - 'full-archive'
            quarantine:
                type: str
                description: Enable/disable quarantine for infected files.
                choices:
                    - 'disable'
                    - 'enable'
            fortiai:
                type: str
                description: Enable/disable scanning of files by FortiAI server.
                choices:
                    - 'disable'
                    - 'monitor'
                    - 'block'
            options:
                type: list
                elements: str
                description: Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
                choices:
                    - 'scan'
                    - 'quarantine'
                    - 'avmonitor'
            malware_stream:
                aliases: ['malware-stream']
                type: str
                description: Enable 0-day malware-stream scanning.
                choices:
                    - 'disable'
                    - 'monitor'
                    - 'block'
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
    - name: Configure POP3 AntiVirus options.
      fortinet.fmgdevice.fmgd_antivirus_profile_pop3:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        profile: <your own value>
        antivirus_profile_pop3:
          # archive_block:
          #   - "encrypted"
          #   - "corrupted"
          #   - "multipart"
          #   - "nested"
          #   - "mailbomb"
          #   - "unhandled"
          #   - "partiallycorrupted"
          #   - "timeout"
          #   - "fileslimit"
          # archive_log:
          #   - "encrypted"
          #   - "corrupted"
          #   - "multipart"
          #   - "nested"
          #   - "mailbomb"
          #   - "unhandled"
          #   - "partiallycorrupted"
          #   - "timeout"
          #   - "fileslimit"
          # av_scan: <value in [disable, monitor, block]>
          # content_disarm: <value in [disable, enable]>
          # emulator: <value in [disable, enable]>
          # executables: <value in [default, virus]>
          # external_blocklist: <value in [disable, monitor, block]>
          # fortindr: <value in [disable, block, monitor]>
          # fortisandbox: <value in [disable, block, monitor]>
          # outbreak_prevention: <value in [disable, block, monitor, ...]>
          # quarantine: <value in [disable, enable]>
          # fortiai: <value in [disable, monitor, block]>
          # options:
          #   - "scan"
          #   - "quarantine"
          #   - "avmonitor"
          # malware_stream: <value in [disable, monitor, block]>
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
        '/pm/config/device/{device}/vdom/{vdom}/antivirus/profile/{profile}/pop3'
    ]
    url_params = ['device', 'vdom', 'profile']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'antivirus_profile_pop3': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                'archive-block': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'],
                    'elements': 'str'
                },
                'archive-log': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'timeout', 'fileslimit'],
                    'elements': 'str'
                },
                'av-scan': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                'content-disarm': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'emulator': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'executables': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                'external-blocklist': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                'fortindr': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'fortisandbox': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'outbreak-prevention': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['disable', 'block', 'monitor', 'files', 'disabled', 'full-archive'],
                    'type': 'str'
                },
                'quarantine': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortiai': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                'options': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'choices': ['scan', 'quarantine', 'avmonitor'],
                    'elements': 'str'
                },
                'malware-stream': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile_pop3'),
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
