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
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
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
        choices: ['fortigate', 'fortiswitch', 'fortiap', 'fortiextender', 'fortiproxy']
      failure_reason:
        aliases: ['failure-reason']
        type: str
        description: Upgrade failure reason.
        choices: ['none', 'internal', 'timeout', 'device-type-unsupported', 'download-failed',
                  'device-missing', 'version-unavailable', 'staging-failed', 'reboot-failed',
                  'device-not-reconnected', 'node-not-ready', 'no-final-confirmation',
                  'no-confirmation-query', 'config-error-log-nonempty', 'node-failed',
                  'csf-tree-not-supported', 'firmware-changed', 'image-missing',
                  'suspension-timeout']
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
        choices: ['disabled', 'initialized', 'downloading', 'ready', 'cancelled', 'confirmed',
                  'done', 'failed', 'device-disconnected', 'staging', 'final-check',
                  'upgrade-devices', 'coordinating', 'dry-run-done']
      time:
        type: list
        elements: str
        description: Scheduled upgrade execution time in UTC
      timing:
        type: str
        description: Run immediately or at a scheduled time.
        choices: ['immediate', 'scheduled']
      upgrade_path:
        aliases: ['upgrade-path']
        type: str
        description: Fortinet OS image versions to upgrade through in major-minor-patch format, such as 7-0-4.
      ignore_signing_errors:
        aliases: ['ignore-signing-errors']
        type: str
        description: Allow/reject use of FortiGate firmware images that are unsigned.
        choices: ['disable', 'enable']
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
      allow_download:
        aliases: ['allow-download']
        type: str
        description: Enable/disable download firmware images.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Independent upgrades for managed devices.
      fortinet.fmgdevice.fmgd_system_deviceupgrade:
        # workspace_locking_adom: <global or your adom name>
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
          # allow_download: <value in [disable, enable]>
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
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_deviceupgrade': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'device-type': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['fortigate', 'fortiswitch', 'fortiap', 'fortiextender', 'fortiproxy'],
                    'type': 'str'
                },
                'failure-reason': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'none', 'internal', 'timeout', 'device-type-unsupported', 'download-failed', 'device-missing', 'version-unavailable',
                        'staging-failed', 'reboot-failed', 'device-not-reconnected', 'node-not-ready', 'no-final-confirmation', 'no-confirmation-query',
                        'config-error-log-nonempty', 'node-failed', 'csf-tree-not-supported', 'firmware-changed', 'image-missing', 'suspension-timeout'
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
                'maximum-minutes': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'serial': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'setup-time': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'status': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': [
                        'disabled', 'initialized', 'downloading', 'ready', 'cancelled', 'confirmed', 'done', 'failed', 'device-disconnected', 'staging',
                        'final-check', 'upgrade-devices', 'coordinating', 'dry-run-done'
                    ],
                    'type': 'str'
                },
                'time': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'timing': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['immediate', 'scheduled'], 'type': 'str'},
                'upgrade-path': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'ignore-signing-errors': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'initial-version': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'next-path-index': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'starter-admin': {'v_range': [['7.6.2', '']], 'type': 'str'},
                'vdom': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'},
                'allow-download': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_deviceupgrade'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
