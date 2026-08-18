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
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
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
        choices: ['disable', 'enable']
      authorization_request_type:
        aliases: ['authorization-request-type']
        type: str
        description: Authorization request type.
        choices: ['certificate', 'serial']
      certificate:
        type: list
        elements: str
        description: Certificate.
      configuration_sync:
        aliases: ['configuration-sync']
        type: str
        description: Configuration sync mode.
        choices: ['default', 'local']
      downstream_access:
        aliases: ['downstream-access']
        type: str
        description: Enable/disable downstream device access to this devices configuration and data.
        choices: ['disable', 'enable']
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
            choices: ['disable', 'enable']
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
        choices: ['default', 'local']
      fabric_workers:
        aliases: ['fabric-workers']
        type: int
        description: Number of worker processes for Security Fabric daemon.
      file_mgmt:
        aliases: ['file-mgmt']
        type: str
        description: Enable/disable Security Fabric daemon file management.
        choices: ['disable', 'enable']
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
        choices: ['disable', 'enable']
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
        choices: ['disable', 'enable']
      saml_configuration_sync:
        aliases: ['saml-configuration-sync']
        type: str
        description: SAML setting configuration synchronization.
        choices: ['default', 'local']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: Source IP address for communication with the upstream FortiGate.
      status:
        type: str
        description: Enable/disable Security Fabric.
        choices: ['disable', 'enable']
      trusted_list:
        aliases: ['trusted-list']
        type: list
        elements: dict
        description: Trusted list.
        suboptions:
          action:
            type: str
            description: Security fabric authorization action.
            choices: ['deny', 'accept']
          authorization_type:
            aliases: ['authorization-type']
            type: str
            description: Authorization type.
            choices: ['certificate', 'serial']
          certificate:
            type: str
            description: Certificate.
          downstream_authorization:
            aliases: ['downstream-authorization']
            type: str
            description: Trust authorizations by this nodes administrator.
            choices: ['disable', 'enable']
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
          guaranteed_seats:
            aliases: ['guaranteed-seats']
            type: int
            description: Guaranteed seats.
          preferred_seats:
            aliases: ['preferred-seats']
            type: int
            description: Preferred seats.
          ca:
            type: list
            elements: str
            description: Name of a CA on the downstreams certificat chain.
          ca_fingerprint:
            aliases: ['ca-fingerprint']
            type: str
            description: SHA512 fingerprint of a CA on the downstreams certificate chain.
          cn:
            type: list
            elements: str
            description: Certificate CNs used by HA members.
          last_use_time:
            aliases: ['last-use-time']
            type: str
            description: Time when an CSF member authorized by this entry was last observed.
          role:
            type: str
            description: Device role to this member.
            choices: ['downstream', 'upstream']
          upgraded:
            type: str
            description: Updrade triggered for upstream auth.
            choices: ['no', 'yes']
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
        choices: ['auto', 'sdwan', 'specify']
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
        choices: ['disable', 'enable']
      license_sharing:
        aliases: ['license-sharing']
        type: str
        description: License sharing.
        choices: ['disable', 'enable']
      preferred_seats:
        aliases: ['preferred-seats']
        type: int
        description: Preferred seats.
      logging_mode:
        aliases: ['logging-mode']
        type: str
        description: Logging mode
        choices: ['default', 'local']
      autoclear_removed_shared_objects:
        aliases: ['autoclear-removed-shared-objects']
        type: str
        description: Control system behavior for deleted shared objects.
        choices: ['disable', 'enable']
      fabric_datasource_exemption:
        aliases: ['fabric-datasource-exemption']
        type: list
        elements: dict
        description: Fabric datasource exemption.
        suboptions:
          name:
            type: str
            description: Name.
          status:
            type: str
            description: Enable/disable the fabric datasource check on the target table.
            choices: ['disable', 'enable']
      fabric_object_change_auto_cascade:
        aliases: ['fabric-object-change-auto-cascade']
        type: str
        description: Enable/disable the cascade mode for fabric objects datasource check.
        choices: ['disable', 'enable']
      shared_objects:
        aliases: ['shared-objects']
        type: list
        elements: dict
        description: Shared objects.
        suboptions:
          name:
            type: str
            description: UID of the source device.
          objects:
            type: list
            elements: dict
            description: Objects.
            suboptions:
              keys:
                type: list
                elements: dict
                description: Keys.
                suboptions:
                  name:
                    type: list
                    elements: str
                    description: Key.
              pathname:
                type: str
                description: CMDB path and object name.
          trusted_list_entry:
            aliases: ['trusted-list-entry']
            type: list
            elements: str
            description: Trusted list entry name.
      upload_shared_objects:
        aliases: ['upload-shared-objects']
        type: str
        description: Configure uploading shared objects entries to the tree.
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
      fortinet.fmgdevice.fmgd_system_csf:
        # workspace_locking_adom: <global or your adom name>
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
          #     guaranteed_seats: <integer>
          #     preferred_seats: <integer>
          #     ca: <list or string>
          #     ca_fingerprint: <string>
          #     cn: <list or string>
          #     last_use_time: <string>
          #     role: <value in [downstream, upstream]>
          #     upgraded: <value in [no, yes]>
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
          # license_sharing: <value in [disable, enable]>
          # preferred_seats: <integer>
          # logging_mode: <value in [default, local]>
          # autoclear_removed_shared_objects: <value in [disable, enable]>
          # fabric_datasource_exemption:
          #   - name: <string>
          #     status: <value in [disable, enable]>
          # fabric_object_change_auto_cascade: <value in [disable, enable]>
          # shared_objects:
          #   - name: <string>
          #     objects:
          #       - keys:
          #           - name: <list or string>
          #         pathname: <string>
          #     trusted_list_entry: <list or string>
          # upload_shared_objects: <value in [disable, enable]>
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
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_csf': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'accept-auth-by-cert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'authorization-request-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                'certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'configuration-sync': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'downstream-access': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'downstream-accprofile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'fabric-connector': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'accprofile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'configuration-write-access': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'serial': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'vdom': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-object-unification': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'fabric-workers': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'file-mgmt': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-quota': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'file-quota-warning': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'fixed-key': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'forticloud-account-enforcement': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'group-name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'group-password': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'log-unification': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'saml-configuration-sync': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['default', 'local'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'trusted-list': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                        'authorization-type': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['certificate', 'serial'], 'type': 'str'},
                        'certificate': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'downstream-authorization': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ha-members': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'index': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'serial': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'guaranteed-seats': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'preferred-seats': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ca': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'ca-fingerprint': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'cn': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'last-use-time': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'role': {'v_range': [['8.0.0', '']], 'choices': ['downstream', 'upstream'], 'type': 'str'},
                        'upgraded': {'v_range': [['8.0.0', '']], 'choices': ['no', 'yes'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'uid': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'upstream': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'upstream-interface': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'upstream-interface-select-method': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['auto', 'sdwan', 'specify'],
                    'type': 'str'
                },
                'upstream-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'fabric-device': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'access-token': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'device-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'https-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'upstream-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'management-port': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'int'},
                'management-ip': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.7']], 'type': 'str'},
                'legacy-authentication': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.4', '7.4.11'], ['7.6.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'license-sharing': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'preferred-seats': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'logging-mode': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['default', 'local'], 'type': 'str'},
                'autoclear-removed-shared-objects': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-datasource-exemption': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'status': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'fabric-object-change-auto-cascade': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'shared-objects': {
                    'v_range': [['8.0.0', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'objects': {
                            'v_range': [['8.0.0', '']],
                            'type': 'list',
                            'options': {
                                'keys': {
                                    'v_range': [['8.0.0', '']],
                                    'no_log': True,
                                    'type': 'list',
                                    'options': {'name': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}},
                                    'elements': 'dict'
                                },
                                'pathname': {'v_range': [['8.0.0', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'trusted-list-entry': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'upload-shared-objects': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_csf'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgd.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
