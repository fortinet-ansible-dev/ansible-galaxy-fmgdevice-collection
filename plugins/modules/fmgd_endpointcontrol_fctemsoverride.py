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
module: fmgd_endpointcontrol_fctemsoverride
short_description: Configure FortiClient Enterprise Management Server
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
    endpointcontrol_fctemsoverride:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            call_timeout:
                aliases: ['call-timeout']
                type: int
                description: FortiClient EMS call timeout in seconds
            capabilities:
                type: list
                elements: str
                description: List of EMS capabilities.
                choices:
                    - 'fabric-auth'
                    - 'silent-approval'
                    - 'websocket'
                    - 'websocket-malware'
                    - 'push-ca-certs'
                    - 'common-tags-api'
                    - 'tenant-id'
                    - 'single-vdom-connector'
                    - 'client-avatars'
                    - 'fgt-sysinfo-api'
                    - 'ztna-server-info'
            certificate_fingerprint:
                aliases: ['certificate-fingerprint']
                type: str
                description: EMS certificate fingerprint.
            cloud_authentication_access_key:
                aliases: ['cloud-authentication-access-key']
                type: str
                description: FortiClient EMS Cloud multitenancy access key
            dirty_reason:
                aliases: ['dirty-reason']
                type: str
                description: Dirty Reason for FortiClient EMS.
                choices:
                    - 'none'
                    - 'mismatched-ems-sn'
            ems_id:
                aliases: ['ems-id']
                type: int
                description: EMS ID in order
            fortinetone_cloud_authentication:
                aliases: ['fortinetone-cloud-authentication']
                type: str
                description: Enable/disable authentication of FortiClient EMS Cloud through FortiCloud account.
                choices:
                    - 'disable'
                    - 'enable'
            https_port:
                aliases: ['https-port']
                type: int
                description: FortiClient EMS HTTPS access port number.
            interface:
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            interface_select_method:
                aliases: ['interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            name:
                type: str
                description: FortiClient Enterprise Management Server
            out_of_sync_threshold:
                aliases: ['out-of-sync-threshold']
                type: int
                description: Outdated resource threshold in seconds
            preserve_ssl_session:
                aliases: ['preserve-ssl-session']
                type: str
                description: Enable/disable preservation of EMS SSL session connection.
                choices:
                    - 'disable'
                    - 'enable'
            pull_avatars:
                aliases: ['pull-avatars']
                type: str
                description: Enable/disable pulling avatars from EMS.
                choices:
                    - 'disable'
                    - 'enable'
            pull_malware_hash:
                aliases: ['pull-malware-hash']
                type: str
                description: Enable/disable pulling FortiClient malware hash from EMS.
                choices:
                    - 'disable'
                    - 'enable'
            pull_sysinfo:
                aliases: ['pull-sysinfo']
                type: str
                description: Enable/disable pulling SysInfo from EMS.
                choices:
                    - 'disable'
                    - 'enable'
            pull_tags:
                aliases: ['pull-tags']
                type: str
                description: Enable/disable pulling FortiClient user tags from EMS.
                choices:
                    - 'disable'
                    - 'enable'
            pull_vulnerabilities:
                aliases: ['pull-vulnerabilities']
                type: str
                description: Enable/disable pulling vulnerabilities from EMS.
                choices:
                    - 'disable'
                    - 'enable'
            send_tags_to_all_vdoms:
                aliases: ['send-tags-to-all-vdoms']
                type: str
                description: Relax restrictions on tags to send all EMS tags to all VDOMs
                choices:
                    - 'disable'
                    - 'enable'
            serial_number:
                aliases: ['serial-number']
                type: str
                description: EMS Serial Number.
            server:
                type: str
                description: FortiClient EMS FQDN or IPv4 address.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: REST API call source IP.
            status:
                type: str
                description: Enable or disable this EMS configuration.
                choices:
                    - 'disable'
                    - 'enable'
            tenant_id:
                aliases: ['tenant-id']
                type: str
                description: EMS Tenant ID.
            trust_ca_cn:
                aliases: ['trust-ca-cn']
                type: str
                description: Enable/disable trust of the EMS certificate issuer
                choices:
                    - 'disable'
                    - 'enable'
            verified_cn:
                aliases: ['verified-cn']
                type: str
                description: EMS certificate CN.
            verifying_ca:
                aliases: ['verifying-ca']
                type: list
                elements: str
                description: Lowest CA cert on Fortigate in verified EMS cert chain.
            websocket_override:
                aliases: ['websocket-override']
                type: str
                description: Enable/disable override behavior for how this FortiGate unit connects to EMS using a WebSocket connection.
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
    - name: Configure FortiClient Enterprise Management Server
      fortinet.fmgdevice.fmgd_endpointcontrol_fctemsoverride:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        endpointcontrol_fctemsoverride:
          ems_id: 0 # Required variable, integer
          # call_timeout: <integer>
          # capabilities:
          #   - "fabric-auth"
          #   - "silent-approval"
          #   - "websocket"
          #   - "websocket-malware"
          #   - "push-ca-certs"
          #   - "common-tags-api"
          #   - "tenant-id"
          #   - "single-vdom-connector"
          #   - "client-avatars"
          #   - "fgt-sysinfo-api"
          #   - "ztna-server-info"
          # certificate_fingerprint: <string>
          # cloud_authentication_access_key: <string>
          # dirty_reason: <value in [none, mismatched-ems-sn]>
          # fortinetone_cloud_authentication: <value in [disable, enable]>
          # https_port: <integer>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # name: <string>
          # out_of_sync_threshold: <integer>
          # preserve_ssl_session: <value in [disable, enable]>
          # pull_avatars: <value in [disable, enable]>
          # pull_malware_hash: <value in [disable, enable]>
          # pull_sysinfo: <value in [disable, enable]>
          # pull_tags: <value in [disable, enable]>
          # pull_vulnerabilities: <value in [disable, enable]>
          # send_tags_to_all_vdoms: <value in [disable, enable]>
          # serial_number: <string>
          # server: <string>
          # source_ip: <string>
          # status: <value in [disable, enable]>
          # tenant_id: <string>
          # trust_ca_cn: <value in [disable, enable]>
          # verified_cn: <string>
          # verifying_ca: <list or string>
          # websocket_override: <value in [disable, enable]>
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
        '/pm/config/device/{device}/vdom/{vdom}/endpoint-control/fctems-override'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'ems_id'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'endpointcontrol_fctemsoverride': {
            'type': 'dict',
            'v_range': [['7.4.3', '']],
            'options': {
                'call-timeout': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'capabilities': {
                    'v_range': [['7.4.3', '']],
                    'type': 'list',
                    'choices': [
                        'fabric-auth', 'silent-approval', 'websocket', 'websocket-malware', 'push-ca-certs', 'common-tags-api', 'tenant-id',
                        'single-vdom-connector', 'client-avatars', 'fgt-sysinfo-api', 'ztna-server-info'
                    ],
                    'elements': 'str'
                },
                'certificate-fingerprint': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'cloud-authentication-access-key': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'dirty-reason': {'v_range': [['7.4.3', '']], 'choices': ['none', 'mismatched-ems-sn'], 'type': 'str'},
                'ems-id': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'fortinetone-cloud-authentication': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'https-port': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'interface': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'name': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'out-of-sync-threshold': {'v_range': [['7.4.3', '']], 'type': 'int'},
                'preserve-ssl-session': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pull-avatars': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pull-malware-hash': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pull-sysinfo': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pull-tags': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pull-vulnerabilities': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'send-tags-to-all-vdoms': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'serial-number': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'server': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tenant-id': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'trust-ca-cn': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'verified-cn': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'verifying-ca': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'websocket-override': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'endpointcontrol_fctemsoverride'),
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
