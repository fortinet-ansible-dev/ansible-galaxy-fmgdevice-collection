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
module: fmgd_system_deviceupgrade
short_description: Independent upgrades for managed devices.
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
    system_deviceupgrade:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            device_type:
                aliases: ['device-type']
                type: str
                description: Fortinet device type.
                choices:
                    - 'fortigate'
                    - 'fortiswitch'
                    - 'fortiap'
                    - 'fortiextender'
            failure_reason:
                aliases: ['failure-reason']
                type: str
                description: Upgrade failure reason.
                choices:
                    - 'none'
                    - 'internal'
                    - 'timeout'
                    - 'device-type-unsupported'
                    - 'download-failed'
                    - 'device-missing'
                    - 'version-unavailable'
                    - 'staging-failed'
                    - 'reboot-failed'
                    - 'device-not-reconnected'
                    - 'node-not-ready'
                    - 'no-final-confirmation'
                    - 'no-confirmation-query'
                    - 'config-error-log-nonempty'
                    - 'node-failed'
                    - 'csf-tree-not-supported'
                    - 'firmware-changed'
            ha_reboot_controller:
                aliases: ['ha-reboot-controller']
                type: str
                description: Serial number of the FortiGate unit that will control the reboot process for the federated upgrade of the HA cluster.
            known_ha_members:
                aliases: ['known-ha-members']
                type: list
                elements: dict
                description: Known ha members.
                suboptions:
                    serial:
                        type: str
                        description: Serial number of HA member
            maximum_minutes:
                aliases: ['maximum-minutes']
                type: int
                description: Maximum number of minutes to allow for immediate upgrade preparation.
            serial:
                type: str
                description: Serial number of the node to include.
            setup_time:
                aliases: ['setup-time']
                type: list
                elements: str
                description: Upgrade preparation start time in UTC
            status:
                type: str
                description: Current status of the upgrade.
                choices:
                    - 'disabled'
                    - 'initialized'
                    - 'downloading'
                    - 'ready'
                    - 'cancelled'
                    - 'confirmed'
                    - 'done'
                    - 'failed'
                    - 'device-disconnected'
                    - 'staging'
                    - 'final-check'
                    - 'upgrade-devices'
                    - 'coordinating'
                    - 'dry-run-done'
            time:
                type: list
                elements: str
                description: Scheduled upgrade execution time in UTC
            timing:
                type: str
                description: Run immediately or at a scheduled time.
                choices:
                    - 'immediate'
                    - 'scheduled'
            upgrade_path:
                aliases: ['upgrade-path']
                type: str
                description: Fortinet OS image versions to upgrade through in major-minor-patch format, such as 7-0-4.
            ignore_signing_errors:
                aliases: ['ignore-signing-errors']
                type: str
                description: Allow/reject use of FortiGate firmware images that are unsigned.
                choices:
                    - 'disable'
                    - 'enable'
            initial_version:
                aliases: ['initial-version']
                type: str
                description: Firmware version when the upgrade was set up.
            next_path_index:
                aliases: ['next-path-index']
                type: int
                description: The index of the next image to upgrade to.
            starter_admin:
                aliases: ['starter-admin']
                type: str
                description: Admin that started the upgrade.
            vdom:
                type: list
                elements: str
                description: Limit upgrade to this virtual domain
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
    - name: Independent upgrades for managed devices.
      fortinet.fmgdevice.fmgd_system_deviceupgrade:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_deviceupgrade:
          # device_type: <value in [fortigate, fortiswitch, fortiap, ...]>
          # failure_reason: <value in [none, internal, timeout, ...]>
          # ha_reboot_controller: <string>
          # known_ha_members:
          #   - serial: <string>
          # maximum_minutes: <integer>
          # serial: <string>
          # setup_time: <list or string>
          # status: <value in [disabled, initialized, downloading, ...]>
          # time: <list or string>
          # timing: <value in [immediate, scheduled]>
          # upgrade_path: <string>
          # ignore_signing_errors: <value in [disable, enable]>
          # initial_version: <string>
          # next_path_index: <integer>
          # starter_admin: <string>
          # vdom: <list or string>
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
        '/pm/config/device/{device}/global/system/device-upgrade'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_deviceupgrade': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'device-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['fortigate', 'fortiswitch', 'fortiap', 'fortiextender'],
                    'type': 'str'
                },
                'failure-reason': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'none', 'internal', 'timeout', 'device-type-unsupported', 'download-failed', 'device-missing', 'version-unavailable',
                        'staging-failed', 'reboot-failed', 'device-not-reconnected', 'node-not-ready', 'no-final-confirmation', 'no-confirmation-query',
                        'config-error-log-nonempty', 'node-failed', 'csf-tree-not-supported', 'firmware-changed'
                    ],
                    'type': 'str'
                },
                'ha-reboot-controller': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'known-ha-members': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'options': {'serial': {'v_range': [['7.4.3', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'maximum-minutes': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'serial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'setup-time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'disabled', 'initialized', 'downloading', 'ready', 'cancelled', 'confirmed', 'done', 'failed', 'device-disconnected', 'staging',
                        'final-check', 'upgrade-devices', 'coordinating', 'dry-run-done'
                    ],
                    'type': 'str'
                },
                'time': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'timing': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['immediate', 'scheduled'], 'type': 'str'},
                'upgrade-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ignore-signing-errors': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'initial-version': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'next-path-index': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'starter-admin': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'vdom': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_deviceupgrade'),
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
