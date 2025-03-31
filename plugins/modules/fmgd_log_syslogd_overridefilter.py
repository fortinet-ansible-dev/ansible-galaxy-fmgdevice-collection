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
module: fmgd_log_syslogd_overridefilter
short_description: Override filters for remote system server.
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
    log_syslogd_overridefilter:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            anomaly:
                type: str
                description: Enable/disable anomaly logging.
                choices:
                    - 'disable'
                    - 'enable'
            forti_switch:
                aliases: ['forti-switch']
                type: str
                description: Enable/disable Forti-Switch logging.
                choices:
                    - 'disable'
                    - 'enable'
            forward_traffic:
                aliases: ['forward-traffic']
                type: str
                description: Enable/disable forward traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            free_style:
                aliases: ['free-style']
                type: list
                elements: dict
                description: Free style.
                suboptions:
                    category:
                        type: str
                        description: Log category.
                        choices:
                            - 'traffic'
                            - 'event'
                            - 'virus'
                            - 'webfilter'
                            - 'attack'
                            - 'spam'
                            - 'voip'
                            - 'dlp'
                            - 'app-ctrl'
                            - 'anomaly'
                            - 'waf'
                            - 'gtp'
                            - 'dns'
                            - 'ssh'
                            - 'ssl'
                            - 'file-filter'
                            - 'icap'
                            - 'ztna'
                            - 'virtual-patch'
                    filter:
                        type: str
                        description: Free style filter string.
                    filter_type:
                        aliases: ['filter-type']
                        type: str
                        description: Include/exclude logs that match the filter.
                        choices:
                            - 'include'
                            - 'exclude'
                    id:
                        type: int
                        description: Entry ID.
            gtp:
                type: str
                description: Enable/disable GTP messages logging.
                choices:
                    - 'disable'
                    - 'enable'
            local_traffic:
                aliases: ['local-traffic']
                type: str
                description: Enable/disable local in or out traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            multicast_traffic:
                aliases: ['multicast-traffic']
                type: str
                description: Enable/disable multicast traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            severity:
                type: str
                description: Lowest severity level to log.
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warning'
                    - 'notification'
                    - 'information'
                    - 'debug'
            sniffer_traffic:
                aliases: ['sniffer-traffic']
                type: str
                description: Enable/disable sniffer traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            voip:
                type: str
                description: Enable/disable VoIP logging.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_traffic:
                aliases: ['ztna-traffic']
                type: str
                description: Enable/disable ztna traffic logging.
                choices:
                    - 'disable'
                    - 'enable'
            filter_type:
                aliases: ['filter-type']
                type: str
                description: Include/exclude logs that match the filter.
                choices:
                    - 'include'
                    - 'exclude'
            filter:
                type: str
                description: Syslog filter.
            http_transaction:
                aliases: ['http-transaction']
                type: str
                description: Enable/disable log HTTP transaction messages.
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Override filters for remote system server.
      fortinet.fmgdevice.fmgd_log_syslogd_overridefilter:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        log_syslogd_overridefilter:
          # anomaly: <value in [disable, enable]>
          # forti_switch: <value in [disable, enable]>
          # forward_traffic: <value in [disable, enable]>
          # free_style:
          #   - category: <value in [traffic, event, virus, ...]>
          #     filter: <string>
          #     filter_type: <value in [include, exclude]>
          #     id: <integer>
          # gtp: <value in [disable, enable]>
          # local_traffic: <value in [disable, enable]>
          # multicast_traffic: <value in [disable, enable]>
          # severity: <value in [emergency, alert, critical, ...]>
          # sniffer_traffic: <value in [disable, enable]>
          # voip: <value in [disable, enable]>
          # ztna_traffic: <value in [disable, enable]>
          # filter_type: <value in [include, exclude]>
          # filter: <string>
          # http_transaction: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'log_syslogd_overridefilter': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'anomaly': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forti-switch': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'forward-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'free-style': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'category': {
                            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                            'choices': [
                                'traffic', 'event', 'virus', 'webfilter', 'attack', 'spam', 'voip', 'dlp', 'app-ctrl', 'anomaly', 'waf', 'gtp', 'dns',
                                'ssh', 'ssl', 'file-filter', 'icap', 'ztna', 'virtual-patch'
                            ],
                            'type': 'str'
                        },
                        'filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'filter-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'gtp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'local-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'multicast-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'severity': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                    'type': 'str'
                },
                'sniffer-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'voip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-traffic': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'filter-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                'filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'http-transaction': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'log_syslogd_overridefilter'),
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
