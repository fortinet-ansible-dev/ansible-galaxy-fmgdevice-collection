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
module: fmgd_system_accprofile
short_description: Configure access profiles for system administrators.
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
    system_accprofile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            admintimeout:
                type: int
                description: Administrator timeout for this access profile
            admintimeout_override:
                aliases: ['admintimeout-override']
                type: str
                description: Enable/disable overriding the global administrator idle timeout.
                choices:
                    - 'disable'
                    - 'enable'
            authgrp:
                type: str
                description: Administrator access to Users and Devices.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            cli_config:
                aliases: ['cli-config']
                type: str
                description: Enable/disable permission to run config commands.
                choices:
                    - 'disable'
                    - 'enable'
            cli_diagnose:
                aliases: ['cli-diagnose']
                type: str
                description: Enable/disable permission to run diagnostic commands.
                choices:
                    - 'disable'
                    - 'enable'
            cli_exec:
                aliases: ['cli-exec']
                type: str
                description: Enable/disable permission to run execute commands.
                choices:
                    - 'disable'
                    - 'enable'
            cli_get:
                aliases: ['cli-get']
                type: str
                description: Enable/disable permission to run get commands.
                choices:
                    - 'disable'
                    - 'enable'
            cli_show:
                aliases: ['cli-show']
                type: str
                description: Enable/disable permission to run show commands.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comment.
            ftviewgrp:
                type: str
                description: FortiView.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            fwgrp:
                type: str
                description: Administrator access to the Firewall configuration.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            fwgrp_permission:
                aliases: ['fwgrp-permission']
                type: dict
                description: Fwgrp permission.
                suboptions:
                    address:
                        type: str
                        description: Address Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    others:
                        type: str
                        description: Other Firewall Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    policy:
                        type: str
                        description: Policy Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    schedule:
                        type: str
                        description: Schedule Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    service:
                        type: str
                        description: Service Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            loggrp:
                type: str
                description: Administrator access to Logging and Reporting including viewing log messages.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            loggrp_permission:
                aliases: ['loggrp-permission']
                type: dict
                description: Loggrp permission.
                suboptions:
                    config:
                        type: str
                        description: Log & Report configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    data_access:
                        aliases: ['data-access']
                        type: str
                        description: Log & Report Data Access.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    report_access:
                        aliases: ['report-access']
                        type: str
                        description: Log & Report Report Access.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    threat_weight:
                        aliases: ['threat-weight']
                        type: str
                        description: Log & Report Threat Weight.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            name:
                type: str
                description: Profile name.
                required: true
            netgrp:
                type: str
                description: Network Configuration.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            netgrp_permission:
                aliases: ['netgrp-permission']
                type: dict
                description: Netgrp permission.
                suboptions:
                    cfg:
                        type: str
                        description: Network Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    packet_capture:
                        aliases: ['packet-capture']
                        type: str
                        description: Packet Capture Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    route_cfg:
                        aliases: ['route-cfg']
                        type: str
                        description: Router Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            scope:
                type: str
                description: Scope of admin access
                choices:
                    - 'vdom'
                    - 'global'
            secfabgrp:
                type: str
                description: Security Fabric.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            sysgrp:
                type: str
                description: System Configuration.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            sysgrp_permission:
                aliases: ['sysgrp-permission']
                type: dict
                description: Sysgrp permission.
                suboptions:
                    admin:
                        type: str
                        description: Administrator Users.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    cfg:
                        type: str
                        description: System Configuration.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    mnt:
                        type: str
                        description: Maintenance.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    upd:
                        type: str
                        description: FortiGuard Updates.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            system_diagnostics:
                aliases: ['system-diagnostics']
                type: str
                description: Enable/disable permission to run system diagnostic commands.
                choices:
                    - 'disable'
                    - 'enable'
            system_execute_ssh:
                aliases: ['system-execute-ssh']
                type: str
                description: Enable/disable permission to execute SSH commands.
                choices:
                    - 'disable'
                    - 'enable'
            system_execute_telnet:
                aliases: ['system-execute-telnet']
                type: str
                description: Enable/disable permission to execute TELNET commands.
                choices:
                    - 'disable'
                    - 'enable'
            utmgrp:
                type: str
                description: Administrator access to Security Profiles.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
                    - 'custom'
            utmgrp_permission:
                aliases: ['utmgrp-permission']
                type: dict
                description: Utmgrp permission.
                suboptions:
                    antivirus:
                        type: str
                        description: Antivirus profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    application_control:
                        aliases: ['application-control']
                        type: str
                        description: Application Control profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    casb:
                        type: str
                        description: Inline CASB filter profile and settings
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    data_leak_prevention:
                        aliases: ['data-leak-prevention']
                        type: str
                        description: DLP profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    dlp:
                        type: str
                        description: DLP profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    dnsfilter:
                        type: str
                        description: DNS Filter profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    emailfilter:
                        type: str
                        description: Email Filter and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    endpoint_control:
                        aliases: ['endpoint-control']
                        type: str
                        description: FortiClient Profiles.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    file_filter:
                        aliases: ['file-filter']
                        type: str
                        description: File-filter profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    icap:
                        type: str
                        description: ICAP profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    ips:
                        type: str
                        description: IPS profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    mmsgtp:
                        type: str
                        description: UTM permission.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    videofilter:
                        type: str
                        description: Video filter profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    virtual_patch:
                        aliases: ['virtual-patch']
                        type: str
                        description: Virtual patch profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    voip:
                        type: str
                        description: VoIP profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    waf:
                        type: str
                        description: Web Application Firewall profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    webfilter:
                        type: str
                        description: Web Filter profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
                    data_loss_prevention:
                        aliases: ['data-loss-prevention']
                        type: str
                        description: DLP profiles and settings.
                        choices:
                            - 'none'
                            - 'read'
                            - 'read-write'
            vpngrp:
                type: str
                description: Administrator access to IPsec, SSL, PPTP, and L2TP VPN.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            wanoptgrp:
                type: str
                description: Administrator access to WAN Opt & Cache.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
            wifi:
                type: str
                description: Administrator access to the WiFi controller and Switch controller.
                choices:
                    - 'none'
                    - 'read'
                    - 'read-write'
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
    - name: Configure access profiles for system administrators.
      fortinet.fmgdevice.fmgd_system_accprofile:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_accprofile:
          name: "your value" # Required variable, string
          # admintimeout: <integer>
          # admintimeout_override: <value in [disable, enable]>
          # authgrp: <value in [none, read, read-write]>
          # cli_config: <value in [disable, enable]>
          # cli_diagnose: <value in [disable, enable]>
          # cli_exec: <value in [disable, enable]>
          # cli_get: <value in [disable, enable]>
          # cli_show: <value in [disable, enable]>
          # comments: <string>
          # ftviewgrp: <value in [none, read, read-write]>
          # fwgrp: <value in [none, read, read-write, ...]>
          # fwgrp_permission:
          #   address: <value in [none, read, read-write]>
          #   others: <value in [none, read, read-write]>
          #   policy: <value in [none, read, read-write]>
          #   schedule: <value in [none, read, read-write]>
          #   service: <value in [none, read, read-write]>
          # loggrp: <value in [none, read, read-write, ...]>
          # loggrp_permission:
          #   config: <value in [none, read, read-write]>
          #   data_access: <value in [none, read, read-write]>
          #   report_access: <value in [none, read, read-write]>
          #   threat_weight: <value in [none, read, read-write]>
          # netgrp: <value in [none, read, read-write, ...]>
          # netgrp_permission:
          #   cfg: <value in [none, read, read-write]>
          #   packet_capture: <value in [none, read, read-write]>
          #   route_cfg: <value in [none, read, read-write]>
          # scope: <value in [vdom, global]>
          # secfabgrp: <value in [none, read, read-write]>
          # sysgrp: <value in [none, read, read-write, ...]>
          # sysgrp_permission:
          #   admin: <value in [none, read, read-write]>
          #   cfg: <value in [none, read, read-write]>
          #   mnt: <value in [none, read, read-write]>
          #   upd: <value in [none, read, read-write]>
          # system_diagnostics: <value in [disable, enable]>
          # system_execute_ssh: <value in [disable, enable]>
          # system_execute_telnet: <value in [disable, enable]>
          # utmgrp: <value in [none, read, read-write, ...]>
          # utmgrp_permission:
          #   antivirus: <value in [none, read, read-write]>
          #   application_control: <value in [none, read, read-write]>
          #   casb: <value in [none, read, read-write]>
          #   data_leak_prevention: <value in [none, read, read-write]>
          #   dlp: <value in [none, read, read-write]>
          #   dnsfilter: <value in [none, read, read-write]>
          #   emailfilter: <value in [none, read, read-write]>
          #   endpoint_control: <value in [none, read, read-write]>
          #   file_filter: <value in [none, read, read-write]>
          #   icap: <value in [none, read, read-write]>
          #   ips: <value in [none, read, read-write]>
          #   mmsgtp: <value in [none, read, read-write]>
          #   videofilter: <value in [none, read, read-write]>
          #   virtual_patch: <value in [none, read, read-write]>
          #   voip: <value in [none, read, read-write]>
          #   waf: <value in [none, read, read-write]>
          #   webfilter: <value in [none, read, read-write]>
          #   data_loss_prevention: <value in [none, read, read-write]>
          # vpngrp: <value in [none, read, read-write]>
          # wanoptgrp: <value in [none, read, read-write]>
          # wifi: <value in [none, read, read-write]>
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
        '/pm/config/device/{device}/global/system/accprofile'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_accprofile': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'admintimeout': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'admintimeout-override': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'cli-config': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cli-diagnose': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cli-exec': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cli-get': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cli-show': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ftviewgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'fwgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write', 'custom'], 'type': 'str'},
                'fwgrp-permission': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'address': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'others': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'policy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'schedule': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'service': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
                    }
                },
                'loggrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write', 'custom'], 'type': 'str'},
                'loggrp-permission': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'config': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'data-access': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'report-access': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'threat-weight': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
                    }
                },
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'netgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write', 'custom'], 'type': 'str'},
                'netgrp-permission': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'cfg': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'packet-capture': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'route-cfg': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
                    }
                },
                'scope': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['vdom', 'global'], 'type': 'str'},
                'secfabgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'sysgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write', 'custom'], 'type': 'str'},
                'sysgrp-permission': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'admin': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'cfg': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'mnt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'upd': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
                    }
                },
                'system-diagnostics': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'system-execute-ssh': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'system-execute-telnet': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'utmgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write', 'custom'], 'type': 'str'},
                'utmgrp-permission': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'antivirus': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'application-control': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'casb': {'v_range': [['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'data-leak-prevention': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'dlp': {'v_range': [['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'dnsfilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'emailfilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'endpoint-control': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'file-filter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'icap': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'ips': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'mmsgtp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'videofilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'virtual-patch': {'v_range': [['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'voip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'waf': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'webfilter': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                        'data-loss-prevention': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
                    }
                },
                'vpngrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'wanoptgrp': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'},
                'wifi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'read', 'read-write'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_accprofile'),
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
