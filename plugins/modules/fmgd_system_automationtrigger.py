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
module: fmgd_system_automationtrigger
short_description: Trigger for automation stitches.
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
    system_automationtrigger:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            description:
                type: str
                description: Description.
            event_type:
                aliases: ['event-type']
                type: str
                description: Event type.
                choices:
                    - 'ioc'
                    - 'event-log'
                    - 'reboot'
                    - 'low-memory'
                    - 'high-cpu'
                    - 'license-near-expiry'
                    - 'ha-failover'
                    - 'config-change'
                    - 'security-rating-summary'
                    - 'virus-ips-db-updated'
                    - 'faz-event'
                    - 'incoming-webhook'
                    - 'fabric-event'
                    - 'ips-logs'
                    - 'anomaly-logs'
                    - 'virus-logs'
                    - 'ssh-logs'
                    - 'webfilter-violation'
                    - 'traffic-violation'
                    - 'local-cert-near-expiry'
                    - 'stitch'
            fabric_event_name:
                aliases: ['fabric-event-name']
                type: str
                description: Fabric connector event handler name.
            fabric_event_severity:
                aliases: ['fabric-event-severity']
                type: str
                description: Fabric connector event severity.
            faz_event_name:
                aliases: ['faz-event-name']
                type: str
                description: FortiAnalyzer event handler name.
            faz_event_severity:
                aliases: ['faz-event-severity']
                type: str
                description: FortiAnalyzer event severity.
            faz_event_tags:
                aliases: ['faz-event-tags']
                type: str
                description: FortiAnalyzer event tags.
            fields:
                type: list
                elements: dict
                description: Fields.
                suboptions:
                    id:
                        type: int
                        description: Entry ID.
                    name:
                        type: str
                        description: Name.
                    value:
                        type: str
                        description: Value.
            license_type:
                aliases: ['license-type']
                type: str
                description: License type.
                choices:
                    - 'forticare-support'
                    - 'fortiguard-webfilter'
                    - 'fortiguard-antispam'
                    - 'fortiguard-antivirus'
                    - 'fortiguard-ips'
                    - 'fortiguard-management'
                    - 'forticloud'
                    - 'any'
            logid:
                type: list
                elements: int
                description: Log IDs to trigger event.
            name:
                type: str
                description: Name.
                required: true
            report_type:
                aliases: ['report-type']
                type: str
                description: Security Rating report.
                choices:
                    - 'posture'
                    - 'coverage'
                    - 'optimization'
                    - 'any'
                    - 'OptimizationReport'
                    - 'PostureReport'
                    - 'CoverageReport'
            serial:
                type: str
                description: Fabric connector serial number.
            trigger_datetime:
                aliases: ['trigger-datetime']
                type: str
                description: Trigger date and time
            trigger_day:
                aliases: ['trigger-day']
                type: int
                description: Day within a month to trigger.
            trigger_frequency:
                aliases: ['trigger-frequency']
                type: str
                description: Scheduled trigger frequency
                choices:
                    - 'daily'
                    - 'weekly'
                    - 'once'
                    - 'monthly'
                    - 'hourly'
            trigger_hour:
                aliases: ['trigger-hour']
                type: int
                description: Hour of the day on which to trigger
            trigger_minute:
                aliases: ['trigger-minute']
                type: int
                description: Minute of the hour on which to trigger
            trigger_type:
                aliases: ['trigger-type']
                type: str
                description: Trigger type.
                choices:
                    - 'event-based'
                    - 'scheduled'
            trigger_weekday:
                aliases: ['trigger-weekday']
                type: str
                description: Day of week for trigger.
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
            vdom:
                type: list
                elements: str
                description: Virtual domain
            ioc_level:
                aliases: ['ioc-level']
                type: str
                description: IOC threat level.
                choices:
                    - 'high'
                    - 'medium'
            stitch_name:
                aliases: ['stitch-name']
                type: list
                elements: str
                description: Triggering stitch name.
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
    - name: Trigger for automation stitches.
      fortinet.fmgdevice.fmgd_system_automationtrigger:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_automationtrigger:
          name: "your value" # Required variable, string
          # description: <string>
          # event_type: <value in [ioc, event-log, reboot, ...]>
          # fabric_event_name: <string>
          # fabric_event_severity: <string>
          # faz_event_name: <string>
          # faz_event_severity: <string>
          # faz_event_tags: <string>
          # fields:
          #   - id: <integer>
          #     name: <string>
          #     value: <string>
          # license_type: <value in [forticare-support, fortiguard-webfilter, fortiguard-antispam, ...]>
          # logid: <list or integer>
          # report_type: <value in [posture, coverage, optimization, ...]>
          # serial: <string>
          # trigger_datetime: <string>
          # trigger_day: <integer>
          # trigger_frequency: <value in [daily, weekly, once, ...]>
          # trigger_hour: <integer>
          # trigger_minute: <integer>
          # trigger_type: <value in [event-based, scheduled]>
          # trigger_weekday: <value in [sunday, monday, tuesday, ...]>
          # vdom: <list or string>
          # ioc_level: <value in [high, medium]>
          # stitch_name: <list or string>
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
        '/pm/config/device/{device}/global/system/automation-trigger'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_automationtrigger': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'description': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'event-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'ioc', 'event-log', 'reboot', 'low-memory', 'high-cpu', 'license-near-expiry', 'ha-failover', 'config-change',
                        'security-rating-summary', 'virus-ips-db-updated', 'faz-event', 'incoming-webhook', 'fabric-event', 'ips-logs', 'anomaly-logs',
                        'virus-logs', 'ssh-logs', 'webfilter-violation', 'traffic-violation', 'local-cert-near-expiry', 'stitch'
                    ],
                    'type': 'str'
                },
                'fabric-event-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fabric-event-severity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'faz-event-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'faz-event-severity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'faz-event-tags': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'fields': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'value': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'license-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'forticare-support', 'fortiguard-webfilter', 'fortiguard-antispam', 'fortiguard-antivirus', 'fortiguard-ips',
                        'fortiguard-management', 'forticloud', 'any'
                    ],
                    'type': 'str'
                },
                'logid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'report-type': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['posture', 'coverage', 'optimization', 'any', 'OptimizationReport', 'PostureReport', 'CoverageReport'],
                    'type': 'str'
                },
                'serial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'trigger-datetime': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'trigger-day': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'trigger-frequency': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['daily', 'weekly', 'once', 'monthly', 'hourly'],
                    'type': 'str'
                },
                'trigger-hour': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'trigger-minute': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'trigger-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['event-based', 'scheduled'], 'type': 'str'},
                'trigger-weekday': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'],
                    'type': 'str'
                },
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ioc-level': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['high', 'medium'], 'type': 'str'},
                'stitch-name': {'v_range': [['7.6.2', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_automationtrigger'),
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
