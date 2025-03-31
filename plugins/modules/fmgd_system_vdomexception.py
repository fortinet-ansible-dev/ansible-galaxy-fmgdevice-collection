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
module: fmgd_system_vdomexception
short_description: Global configuration objects that can be configured independently across different ha peers for all VDOMs or for the defined VDOM scope.
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
    system_vdomexception:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            id:
                type: int
                description: Index
                required: true
            object:
                type: str
                description: Name of the configuration object that can be configured independently for all VDOMs.
                choices:
                    - 'log.fortianalyzer.setting'
                    - 'log.fortianalyzer.override-setting'
                    - 'vpn.ipsec.phase1-interface'
                    - 'vpn.ipsec.phase2-interface'
                    - 'router.bgp'
                    - 'router.route-map'
                    - 'router.prefix-list'
                    - 'firewall.ippool'
                    - 'log.fortianalyzer2.setting'
                    - 'log.fortianalyzer2.override-setting'
                    - 'log.fortianalyzer3.setting'
                    - 'log.fortianalyzer3.override-setting'
                    - 'log.fortianalyzer-cloud.setting'
                    - 'log.fortianalyzer-cloud.override-setting'
                    - 'system.central-management'
                    - 'system.csf'
                    - 'user.radius'
                    - 'system.virtual-wan-link'
                    - 'log.syslogd.setting'
                    - 'log.syslogd.override-setting'
                    - 'log.syslogd2.setting'
                    - 'log.syslogd2.override-setting'
                    - 'log.syslogd3.setting'
                    - 'log.syslogd3.override-setting'
                    - 'log.syslogd4.setting'
                    - 'log.syslogd4.override-setting'
                    - 'firewall.vip'
                    - 'firewall.vip6'
                    - 'firewall.vip46'
                    - 'firewall.vip64'
                    - 'firewall.ippool6'
                    - 'router.static'
                    - 'router.static6'
                    - 'system.interface'
                    - 'system.sdwan'
                    - 'system.saml'
                    - 'router.policy'
                    - 'router.policy6'
                    - 'system.gre-tunnel'
                    - 'system.cluster-sync'
                    - 'system.standalone-cluster'
                    - 'system.snmp.sysinfo'
                    - 'system.snmp.community'
                    - 'system.snmp.user'
                    - 'firewall.address'
            oid:
                type: int
                description: Object ID.
            scope:
                type: str
                description: Determine whether the configuration object can be configured separately for all VDOMs or if some VDOMs share the same conf...
                choices:
                    - 'all'
                    - 'inclusive'
                    - 'exclusive'
            vdom:
                type: list
                elements: str
                description: Names of the VDOMs.
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
    - name: Global configuration objects that can be configured independently across different ha peers for all VDOMs or for the defined VDOM scope.
      fortinet.fmgdevice.fmgd_system_vdomexception:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_vdomexception:
          id: 0 # Required variable, integer
          # object: <value in [log.fortianalyzer.setting, log.fortianalyzer.override-setting, vpn.ipsec.phase1-interface, ...]>
          # oid: <integer>
          # scope: <value in [all, inclusive, exclusive]>
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
        '/pm/config/device/{device}/global/system/vdom-exception'
    ]
    url_params = ['device']
    module_primary_key = 'id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_vdomexception': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'id': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'int'},
                'object': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': [
                        'log.fortianalyzer.setting', 'log.fortianalyzer.override-setting', 'vpn.ipsec.phase1-interface', 'vpn.ipsec.phase2-interface',
                        'router.bgp', 'router.route-map', 'router.prefix-list', 'firewall.ippool', 'log.fortianalyzer2.setting',
                        'log.fortianalyzer2.override-setting', 'log.fortianalyzer3.setting', 'log.fortianalyzer3.override-setting',
                        'log.fortianalyzer-cloud.setting', 'log.fortianalyzer-cloud.override-setting', 'system.central-management', 'system.csf',
                        'user.radius', 'system.virtual-wan-link', 'log.syslogd.setting', 'log.syslogd.override-setting', 'log.syslogd2.setting',
                        'log.syslogd2.override-setting', 'log.syslogd3.setting', 'log.syslogd3.override-setting', 'log.syslogd4.setting',
                        'log.syslogd4.override-setting', 'firewall.vip', 'firewall.vip6', 'firewall.vip46', 'firewall.vip64', 'firewall.ippool6',
                        'router.static', 'router.static6', 'system.interface', 'system.sdwan', 'system.saml', 'router.policy', 'router.policy6',
                        'system.gre-tunnel', 'system.cluster-sync', 'system.standalone-cluster', 'system.snmp.sysinfo', 'system.snmp.community',
                        'system.snmp.user', 'firewall.address'
                    ],
                    'type': 'str'
                },
                'oid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'scope': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['all', 'inclusive', 'exclusive'], 'type': 'str'},
                'vdom': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_vdomexception'),
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
