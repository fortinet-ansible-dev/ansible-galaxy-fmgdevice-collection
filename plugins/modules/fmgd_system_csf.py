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
module: fmgd_system_csf
short_description: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
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
    system_csf:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            accept_auth_by_cert:
                aliases: ['accept-auth-by-cert']
                type: str
                description: Accept connections with unknown certificates and ask admin for approval.
                choices:
                    - 'disable'
                    - 'enable'
            authorization_request_type:
                aliases: ['authorization-request-type']
                type: str
                description: Authorization request type.
                choices:
                    - 'certificate'
                    - 'serial'
            certificate:
                type: list
                elements: str
                description: Certificate.
            configuration_sync:
                aliases: ['configuration-sync']
                type: str
                description: Configuration sync mode.
                choices:
                    - 'default'
                    - 'local'
            downstream_access:
                aliases: ['downstream-access']
                type: str
                description: Enable/disable downstream device access to this devices configuration and data.
                choices:
                    - 'disable'
                    - 'enable'
            downstream_accprofile:
                aliases: ['downstream-accprofile']
                type: list
                elements: str
                description: Default access profile for requests from downstream devices.
            fabric_connector:
                aliases: ['fabric-connector']
                type: list
                elements: dict
                description: Fabric connector.
                suboptions:
                    accprofile:
                        type: list
                        elements: str
                        description: Override access profile.
                    configuration_write_access:
                        aliases: ['configuration-write-access']
                        type: str
                        description: Enable/disable downstream device write access to configuration.
                        choices:
                            - 'disable'
                            - 'enable'
                    serial:
                        type: str
                        description: Serial.
                    vdom:
                        type: list
                        elements: str
                        description: Virtual domains that the connector has access to.
            fabric_object_unification:
                aliases: ['fabric-object-unification']
                type: str
                description: Fabric CMDB Object Unification.
                choices:
                    - 'default'
                    - 'local'
            fabric_workers:
                aliases: ['fabric-workers']
                type: int
                description: Number of worker processes for Security Fabric daemon.
            file_mgmt:
                aliases: ['file-mgmt']
                type: str
                description: Enable/disable Security Fabric daemon file management.
                choices:
                    - 'disable'
                    - 'enable'
            file_quota:
                aliases: ['file-quota']
                type: int
                description: Maximum amount of memory that can be used by the daemon files
            file_quota_warning:
                aliases: ['file-quota-warning']
                type: int
                description: Warn when the set percentage of quota has been used.
            fixed_key:
                aliases: ['fixed-key']
                type: list
                elements: str
                description: Auto-generated fixed key used when this device is the root.
            forticloud_account_enforcement:
                aliases: ['forticloud-account-enforcement']
                type: str
                description: Fabric FortiCloud account unification.
                choices:
                    - 'disable'
                    - 'enable'
            group_name:
                aliases: ['group-name']
                type: str
                description: Security Fabric group name.
            group_password:
                aliases: ['group-password']
                type: list
                elements: str
                description: Security Fabric group password.
            log_unification:
                aliases: ['log-unification']
                type: str
                description: Enable/disable broadcast of discovery messages for log unification.
                choices:
                    - 'disable'
                    - 'enable'
            saml_configuration_sync:
                aliases: ['saml-configuration-sync']
                type: str
                description: SAML setting configuration synchronization.
                choices:
                    - 'default'
                    - 'local'
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address for communication with the upstream FortiGate.
            status:
                type: str
                description: Enable/disable Security Fabric.
                choices:
                    - 'disable'
                    - 'enable'
            trusted_list:
                aliases: ['trusted-list']
                type: list
                elements: dict
                description: Trusted list.
                suboptions:
                    action:
                        type: str
                        description: Security fabric authorization action.
                        choices:
                            - 'deny'
                            - 'accept'
                    authorization_type:
                        aliases: ['authorization-type']
                        type: str
                        description: Authorization type.
                        choices:
                            - 'certificate'
                            - 'serial'
                    certificate:
                        type: str
                        description: Certificate.
                    downstream_authorization:
                        aliases: ['downstream-authorization']
                        type: str
                        description: Trust authorizations by this nodes administrator.
                        choices:
                            - 'disable'
                            - 'enable'
                    ha_members:
                        aliases: ['ha-members']
                        type: list
                        elements: str
                        description: HA members.
                    index:
                        type: int
                        description: Index of the downstream in tree.
                    name:
                        type: str
                        description: Name.
                    serial:
                        type: str
                        description: Serial.
            uid:
                type: str
                description: Unique ID of the current CSF node
            upstream:
                type: str
                description: IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.
            upstream_interface:
                aliases: ['upstream-interface']
                type: list
                elements: str
                description: Specify outgoing interface to reach server.
            upstream_interface_select_method:
                aliases: ['upstream-interface-select-method']
                type: str
                description: Specify how to select outgoing interface to reach server.
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            upstream_port:
                aliases: ['upstream-port']
                type: int
                description: The port number to use to communicate with the FortiGate upstream from this FortiGate in the Security Fabric
            fabric_device:
                aliases: ['fabric-device']
                type: list
                elements: dict
                description: Fabric device.
                suboptions:
                    access_token:
                        aliases: ['access-token']
                        type: list
                        elements: str
                        description: Device access token.
                    device_ip:
                        aliases: ['device-ip']
                        type: str
                        description: Device IP.
                    https_port:
                        aliases: ['https-port']
                        type: int
                        description: HTTPS port for fabric device.
                    name:
                        type: str
                        description: Device name.
            upstream_ip:
                aliases: ['upstream-ip']
                type: str
                description: IP address of the FortiGate upstream from this FortiGate in the Security Fabric.
            management_port:
                aliases: ['management-port']
                type: int
                description: Overriding port for management connection
            management_ip:
                aliases: ['management-ip']
                type: str
                description: Management IP address of this FortiGate.
            legacy_authentication:
                aliases: ['legacy-authentication']
                type: str
                description: Enable/disable legacy authentication.
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
    - name: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
      fortinet.fmgdevice.fmgd_system_csf:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        system_csf:
          # accept_auth_by_cert: <value in [disable, enable]>
          # authorization_request_type: <value in [certificate, serial]>
          # certificate: <list or string>
          # configuration_sync: <value in [default, local]>
          # downstream_access: <value in [disable, enable]>
          # downstream_accprofile: <list or string>
          # fabric_connector:
          #   - accprofile: <list or string>
          #     configuration_write_access: <value in [disable, enable]>
          #     serial: <string>
          #     vdom: <list or string>
          # fabric_object_unification: <value in [default, local]>
          # fabric_workers: <integer>
          # file_mgmt: <value in [disable, enable]>
          # file_quota: <integer>
          # file_quota_warning: <integer>
          # fixed_key: <list or string>
          # forticloud_account_enforcement: <value in [disable, enable]>
          # group_name: <string>
          # group_password: <list or string>
          # log_unification: <value in [disable, enable]>
          # saml_configuration_sync: <value in [default, local]>
          # source_ip: <string>
          # status: <value in [disable, enable]>
          # trusted_list:
          #   - action: <value in [deny, accept]>
          #     authorization_type: <value in [certificate, serial]>
          #     certificate: <string>
          #     downstream_authorization: <value in [disable, enable]>
          #     ha_members: <list or string>
          #     index: <integer>
          #     name: <string>
          #     serial: <string>
          # uid: <string>
          # upstream: <string>
          # upstream_interface: <list or string>
          # upstream_interface_select_method: <value in [auto, sdwan, specify]>
          # upstream_port: <integer>
          # fabric_device:
          #   - access_token: <list or string>
          #     device_ip: <string>
          #     https_port: <integer>
          #     name: <string>
          # upstream_ip: <string>
          # management_port: <integer>
          # management_ip: <string>
          # legacy_authentication: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/csf'
    ]
    url_params = ['device']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_csf': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'accept-auth-by-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authorization-request-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                'certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'configuration-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'downstream-access': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'downstream-accprofile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fabric-connector': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'accprofile': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'configuration-write-access': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'serial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'vdom': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-object-unification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'fabric-workers': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'file-mgmt': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-quota': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'file-quota-warning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fixed-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'forticloud-account-enforcement': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'group-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'log-unification': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-configuration-sync': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trusted-list': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                        'authorization-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                        'certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'downstream-authorization': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ha-members': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'index': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'serial': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'uid': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'upstream': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'upstream-interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'upstream-interface-select-method': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'upstream-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'fabric-device': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-token': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'device-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'https-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'upstream-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'management-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'management-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'legacy-authentication': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.4', '7.4.5'], ['7.6.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf'),
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
