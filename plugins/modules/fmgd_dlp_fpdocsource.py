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
module: fmgd_dlp_fpdocsource
short_description: Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints.
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
    dlp_fpdocsource:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            date:
                type: int
                description: Day of the month on which to scan the server
            file_path:
                aliases: ['file-path']
                type: str
                description: Path on the server to the fingerprint files
            file_pattern:
                aliases: ['file-pattern']
                type: str
                description: Files matching this pattern on the server are fingerprinted.
            keep_modified:
                aliases: ['keep-modified']
                type: str
                description: Enable so that when a file is changed on the server the FortiGate keeps the old fingerprint and adds a new fingerprint to ...
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Name of the DLP fingerprint database.
                required: true
            password:
                type: list
                elements: str
                description: Password required to log into the file server.
            period:
                type: str
                description: Frequency for which the FortiGate checks the server for new or changed files.
                choices:
                    - 'none'
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            remove_deleted:
                aliases: ['remove-deleted']
                type: str
                description: Enable to keep the fingerprint database up to date when a file is deleted from the server.
                choices:
                    - 'disable'
                    - 'enable'
            scan_on_creation:
                aliases: ['scan-on-creation']
                type: str
                description: Enable to keep the fingerprint database up to date when a file is added or changed on the server.
                choices:
                    - 'disable'
                    - 'enable'
            scan_subdirectories:
                aliases: ['scan-subdirectories']
                type: str
                description: Enable/disable scanning subdirectories to find files to create fingerprints from.
                choices:
                    - 'disable'
                    - 'enable'
            sensitivity:
                type: list
                elements: str
                description: Select a sensitivity or threat level for matches with this fingerprint database.
            server:
                type: str
                description: IPv4 or IPv6 address of the server.
            server_type:
                aliases: ['server-type']
                type: str
                description: Protocol used to communicate with the file server.
                choices:
                    - 'samba'
            tod_hour:
                aliases: ['tod-hour']
                type: int
                description: Hour of the day on which to scan the server
            tod_min:
                aliases: ['tod-min']
                type: int
                description: Minute of the hour on which to scan the server
            username:
                type: str
                description: User name required to log into the file server.
            vdom:
                type: str
                description: Select the VDOM that can communicate with the file server.
                choices:
                    - 'mgmt'
                    - 'current'
            weekday:
                type: str
                description: Day of the week on which to scan the server.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
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
    - name: Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints.
      fortinet.fmgdevice.fmgd_dlp_fpdocsource:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        dlp_fpdocsource:
          name: "your value" # Required variable, string
          # date: <integer>
          # file_path: <string>
          # file_pattern: <string>
          # keep_modified: <value in [disable, enable]>
          # password: <list or string>
          # period: <value in [none, daily, weekly, ...]>
          # remove_deleted: <value in [disable, enable]>
          # scan_on_creation: <value in [disable, enable]>
          # scan_subdirectories: <value in [disable, enable]>
          # sensitivity: <list or string>
          # server: <string>
          # server_type: <value in [samba]>
          # tod_hour: <integer>
          # tod_min: <integer>
          # username: <string>
          # vdom: <value in [mgmt, current]>
          # weekday: <value in [sunday, monday, tuesday, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/dlp/fp-doc-source'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'dlp_fpdocsource': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'date': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'file-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'file-pattern': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'keep-modified': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'daily', 'weekly', 'monthly'], 'type': 'str'},
                'remove-deleted': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-on-creation': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-subdirectories': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sensitivity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'server-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['samba'], 'type': 'str'},
                'tod-hour': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'tod-min': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['mgmt', 'current'], 'type': 'str'},
                'weekday': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_fpdocsource'),
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
