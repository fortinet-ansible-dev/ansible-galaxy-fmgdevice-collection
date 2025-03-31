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
module: fmgd_switchcontroller_global
short_description: Configure FortiSwitch global settings.
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
    switchcontroller_global:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bounce_quarantined_link:
                aliases: ['bounce-quarantined-link']
                type: str
                description: Enable/disable bouncing
                choices:
                    - 'disable'
                    - 'enable'
            custom_command:
                aliases: ['custom-command']
                type: list
                elements: dict
                description: Custom command.
                suboptions:
                    command_entry:
                        aliases: ['command-entry']
                        type: str
                        description: List of FortiSwitch commands.
                    command_name:
                        aliases: ['command-name']
                        type: list
                        elements: str
                        description: Name of custom command to push to all FortiSwitches in VDOM.
            default_virtual_switch_vlan:
                aliases: ['default-virtual-switch-vlan']
                type: list
                elements: str
                description: Default VLAN for ports when added to the virtual-switch.
            dhcp_option82_circuit_id:
                aliases: ['dhcp-option82-circuit-id']
                type: list
                elements: str
                description: List the parameters to be included to inform about client identification.
                choices:
                    - 'intfname'
                    - 'vlan'
                    - 'hostname'
                    - 'mode'
                    - 'description'
            dhcp_option82_format:
                aliases: ['dhcp-option82-format']
                type: str
                description: DHCP option-82 format string.
                choices:
                    - 'ascii'
                    - 'legacy'
            dhcp_option82_remote_id:
                aliases: ['dhcp-option82-remote-id']
                type: list
                elements: str
                description: List the parameters to be included to inform about client identification.
                choices:
                    - 'mac'
                    - 'hostname'
                    - 'ip'
            dhcp_server_access_list:
                aliases: ['dhcp-server-access-list']
                type: str
                description: Enable/disable DHCP snooping server access list.
                choices:
                    - 'disable'
                    - 'enable'
            dhcp_snoop_client_db_exp:
                aliases: ['dhcp-snoop-client-db-exp']
                type: int
                description: Expiry time for DHCP snooping server database entries
            dhcp_snoop_client_req:
                aliases: ['dhcp-snoop-client-req']
                type: str
                description: Client DHCP packet broadcast mode.
                choices:
                    - 'drop-untrusted'
                    - 'forward-untrusted'
            dhcp_snoop_db_per_port_learn_limit:
                aliases: ['dhcp-snoop-db-per-port-learn-limit']
                type: int
                description: Per Interface dhcp-server entries learn limit
            disable_discovery:
                aliases: ['disable-discovery']
                type: list
                elements: str
                description: Prevent this FortiSwitch from discovering.
            fips_enforce:
                aliases: ['fips-enforce']
                type: str
                description: Enable/disable enforcement of FIPS on managed FortiSwitch devices.
                choices:
                    - 'disable'
                    - 'enable'
            firmware_provision_on_authorization:
                aliases: ['firmware-provision-on-authorization']
                type: str
                description: Enable/disable automatic provisioning of latest firmware on authorization.
                choices:
                    - 'disable'
                    - 'enable'
            https_image_push:
                aliases: ['https-image-push']
                type: str
                description: Enable/disable image push to FortiSwitch using HTTPS.
                choices:
                    - 'disable'
                    - 'enable'
            log_mac_limit_violations:
                aliases: ['log-mac-limit-violations']
                type: str
                description: Enable/disable logs for Learning Limit Violations.
                choices:
                    - 'disable'
                    - 'enable'
            mac_aging_interval:
                aliases: ['mac-aging-interval']
                type: int
                description: Time after which an inactive MAC is aged out
            mac_event_logging:
                aliases: ['mac-event-logging']
                type: str
                description: Enable/disable MAC address event logging.
                choices:
                    - 'disable'
                    - 'enable'
            mac_retention_period:
                aliases: ['mac-retention-period']
                type: int
                description: Time in hours after which an inactive MAC is removed from client DB
            mac_violation_timer:
                aliases: ['mac-violation-timer']
                type: int
                description: Set timeout for Learning Limit Violations
            quarantine_mode:
                aliases: ['quarantine-mode']
                type: str
                description: Quarantine mode.
                choices:
                    - 'by-vlan'
                    - 'by-redirect'
            sn_dns_resolution:
                aliases: ['sn-dns-resolution']
                type: str
                description: Enable/disable DNS resolution of the FortiSwitch units IP address with switch name.
                choices:
                    - 'disable'
                    - 'enable'
            update_user_device:
                aliases: ['update-user-device']
                type: list
                elements: str
                description: Control which sources update the device user list.
                choices:
                    - 'mac-cache'
                    - 'lldp'
                    - 'dhcp-snooping'
                    - 'l2-db'
                    - 'l3-db'
            vlan_all_mode:
                aliases: ['vlan-all-mode']
                type: str
                description: VLAN configuration mode, user-defined-vlans or all-possible-vlans.
                choices:
                    - 'defined'
                    - 'all'
            vlan_identity:
                aliases: ['vlan-identity']
                type: str
                description: Identity of the VLAN.
                choices:
                    - 'description'
                    - 'name'
            vlan_optimization:
                aliases: ['vlan-optimization']
                type: str
                description: FortiLink VLAN optimization.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'prune'
                    - 'configured'
                    - 'none'
            allow_multiple_interfaces:
                aliases: ['allow-multiple-interfaces']
                type: str
                description: Enable/disable multiple FortiLink interfaces for redundant connections between a managed FortiSwitch and FortiGate.
                choices:
                    - 'disable'
                    - 'enable'
            switch_on_deauth:
                aliases: ['switch-on-deauth']
                type: str
                description: No-operation/Factory-reset the managed FortiSwitch on deauthorization.
                choices:
                    - 'no-op'
                    - 'factory-reset'
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
    - name: Configure FortiSwitch global settings.
      fortinet.fmgdevice.fmgd_switchcontroller_global:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        switchcontroller_global:
          # bounce_quarantined_link: <value in [disable, enable]>
          # custom_command:
          #   - command_entry: <string>
          #     command_name: <list or string>
          # default_virtual_switch_vlan: <list or string>
          # dhcp_option82_circuit_id:
          #   - "intfname"
          #   - "vlan"
          #   - "hostname"
          #   - "mode"
          #   - "description"
          # dhcp_option82_format: <value in [ascii, legacy]>
          # dhcp_option82_remote_id:
          #   - "mac"
          #   - "hostname"
          #   - "ip"
          # dhcp_server_access_list: <value in [disable, enable]>
          # dhcp_snoop_client_db_exp: <integer>
          # dhcp_snoop_client_req: <value in [drop-untrusted, forward-untrusted]>
          # dhcp_snoop_db_per_port_learn_limit: <integer>
          # disable_discovery: <list or string>
          # fips_enforce: <value in [disable, enable]>
          # firmware_provision_on_authorization: <value in [disable, enable]>
          # https_image_push: <value in [disable, enable]>
          # log_mac_limit_violations: <value in [disable, enable]>
          # mac_aging_interval: <integer>
          # mac_event_logging: <value in [disable, enable]>
          # mac_retention_period: <integer>
          # mac_violation_timer: <integer>
          # quarantine_mode: <value in [by-vlan, by-redirect]>
          # sn_dns_resolution: <value in [disable, enable]>
          # update_user_device:
          #   - "mac-cache"
          #   - "lldp"
          #   - "dhcp-snooping"
          #   - "l2-db"
          #   - "l3-db"
          # vlan_all_mode: <value in [defined, all]>
          # vlan_identity: <value in [description, name]>
          # vlan_optimization: <value in [disable, enable, prune, ...]>
          # allow_multiple_interfaces: <value in [disable, enable]>
          # switch_on_deauth: <value in [no-op, factory-reset]>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/global'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_global': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'bounce-quarantined-link': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'custom-command': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'command-entry': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'command-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'default-virtual-switch-vlan': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'dhcp-option82-circuit-id': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': ['intfname', 'vlan', 'hostname', 'mode', 'description'],
                    'elements': 'str'
                },
                'dhcp-option82-format': {'v_range': [['7.4.3', '']], 'choices': ['ascii', 'legacy'], 'type': 'str'},
                'dhcp-option82-remote-id': {'v_range': [['7.4.3', '']], 'type': 'list', 'choices': ['mac', 'hostname', 'ip'], 'elements': 'str'},
                'dhcp-server-access-list': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dhcp-snoop-client-db-exp': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'dhcp-snoop-client-req': {'v_range': [['7.4.3', '']], 'choices': ['drop-untrusted', 'forward-untrusted'], 'type': 'str'},
                'dhcp-snoop-db-per-port-learn-limit': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'disable-discovery': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fips-enforce': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'firmware-provision-on-authorization': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'https-image-push': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'log-mac-limit-violations': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-aging-interval': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mac-event-logging': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mac-retention-period': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'mac-violation-timer': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'quarantine-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['by-vlan', 'by-redirect'], 'type': 'str'},
                'sn-dns-resolution': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'update-user-device': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'choices': ['mac-cache', 'lldp', 'dhcp-snooping', 'l2-db', 'l3-db'],
                    'elements': 'str'
                },
                'vlan-all-mode': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['defined', 'all'], 'type': 'str'},
                'vlan-identity': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['description', 'name'], 'type': 'str'},
                'vlan-optimization': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['disable', 'enable', 'prune', 'configured', 'none'],
                    'type': 'str'
                },
                'allow-multiple-interfaces': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'switch-on-deauth': {'v_range': [['7.6.2', '']], 'choices': ['no-op', 'factory-reset'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_global'),
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
