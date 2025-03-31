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
module: fmgd_vpn_certificate_local
short_description: Local keys and certificates.
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
    vpn_certificate_local:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            acme_ca_url:
                aliases: ['acme-ca-url']
                type: str
                description: The URL for the ACME CA server
            acme_domain:
                aliases: ['acme-domain']
                type: str
                description: A valid domain that resolves to this FortiGate unit.
            acme_email:
                aliases: ['acme-email']
                type: str
                description: Contact email address that is required by some CAs like LetsEncrypt.
            acme_renew_window:
                aliases: ['acme-renew-window']
                type: int
                description: Beginning of the renewal window
            acme_rsa_key_size:
                aliases: ['acme-rsa-key-size']
                type: int
                description: Length of the RSA private key of the generated cert
            auto_regenerate_days:
                aliases: ['auto-regenerate-days']
                type: int
                description: Number of days to wait before expiry of an updated local certificate is requested
            auto_regenerate_days_warning:
                aliases: ['auto-regenerate-days-warning']
                type: int
                description: Number of days to wait before an expiry warning message is generated
            ca_identifier:
                aliases: ['ca-identifier']
                type: str
                description: CA identifier of the CA server for signing via SCEP.
            certificate:
                type: str
                description: PEM format certificate.
            cmp_path:
                aliases: ['cmp-path']
                type: str
                description: Path location inside CMP server.
            cmp_regeneration_method:
                aliases: ['cmp-regeneration-method']
                type: str
                description: CMP auto-regeneration method.
                choices:
                    - 'keyupate'
                    - 'renewal'
            cmp_server:
                aliases: ['cmp-server']
                type: str
                description: Address and port for CMP server
            cmp_server_cert:
                aliases: ['cmp-server-cert']
                type: list
                elements: str
                description: CMP server certificate.
            comments:
                type: str
                description: Comment.
            csr:
                type: str
                description: Certificate Signing Request.
            enroll_protocol:
                aliases: ['enroll-protocol']
                type: str
                description: Certificate enrollment protocol.
                choices:
                    - 'none'
                    - 'scep'
                    - 'cmpv2'
                    - 'acme2'
                    - 'est'
            est_ca_id:
                aliases: ['est-ca-id']
                type: str
                description: CA identifier of the CA server for signing via EST.
            est_client_cert:
                aliases: ['est-client-cert']
                type: list
                elements: str
                description: Certificate used to authenticate this FortiGate to EST server.
            est_http_password:
                aliases: ['est-http-password']
                type: str
                description: HTTP Authentication password for signing via EST.
            est_http_username:
                aliases: ['est-http-username']
                type: str
                description: HTTP Authentication username for signing via EST.
            est_server:
                aliases: ['est-server']
                type: str
                description: Address and port for EST server
            est_server_cert:
                aliases: ['est-server-cert']
                type: list
                elements: str
                description: EST servers certificate must be verifiable by this certificate to be authenticated.
            est_srp_password:
                aliases: ['est-srp-password']
                type: str
                description: EST SRP authentication password.
            est_srp_username:
                aliases: ['est-srp-username']
                type: str
                description: EST SRP authentication username.
            ike_localid:
                aliases: ['ike-localid']
                type: str
                description: Local ID the FortiGate uses for authentication as a VPN client.
            ike_localid_type:
                aliases: ['ike-localid-type']
                type: str
                description: IKE local ID type.
                choices:
                    - 'fqdn'
                    - 'asn1dn'
            last_updated:
                aliases: ['last-updated']
                type: int
                description: Time at which certificate was last updated.
            name:
                type: str
                description: Name.
                required: true
            name_encoding:
                aliases: ['name-encoding']
                type: str
                description: Name encoding method for auto-regeneration.
                choices:
                    - 'printable'
                    - 'utf8'
            password:
                type: list
                elements: str
                description: Password as a PEM file.
            private_key:
                aliases: ['private-key']
                type: str
                description: PEM format key encrypted with a password.
            private_key_retain:
                aliases: ['private-key-retain']
                type: str
                description: Enable/disable retention of private key during SCEP renewal
                choices:
                    - 'disable'
                    - 'enable'
            range:
                type: str
                description: Either a global or VDOM IP address range for the certificate.
                choices:
                    - 'global'
                    - 'vdom'
            scep_password:
                aliases: ['scep-password']
                type: list
                elements: str
                description: SCEP server challenge password for auto-regeneration.
            scep_url:
                aliases: ['scep-url']
                type: str
                description: SCEP server URL.
            source:
                type: str
                description: Certificate source type.
                choices:
                    - 'factory'
                    - 'user'
                    - 'bundle'
                    - 'fortiguard'
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address for communications to the SCEP server.
            state:
                type: str
                description: State.
            tmp_cert_file:
                aliases: ['tmp-cert-file']
                type: str
                description: Temporary certificate file.
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
    - name: Local keys and certificates.
      fortinet.fmgdevice.fmgd_vpn_certificate_local:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        vpn_certificate_local:
          name: "your value" # Required variable, string
          # acme_ca_url: <string>
          # acme_domain: <string>
          # acme_email: <string>
          # acme_renew_window: <integer>
          # acme_rsa_key_size: <integer>
          # auto_regenerate_days: <integer>
          # auto_regenerate_days_warning: <integer>
          # ca_identifier: <string>
          # certificate: <string>
          # cmp_path: <string>
          # cmp_regeneration_method: <value in [keyupate, renewal]>
          # cmp_server: <string>
          # cmp_server_cert: <list or string>
          # comments: <string>
          # csr: <string>
          # enroll_protocol: <value in [none, scep, cmpv2, ...]>
          # est_ca_id: <string>
          # est_client_cert: <list or string>
          # est_http_password: <string>
          # est_http_username: <string>
          # est_server: <string>
          # est_server_cert: <list or string>
          # est_srp_password: <string>
          # est_srp_username: <string>
          # ike_localid: <string>
          # ike_localid_type: <value in [fqdn, asn1dn]>
          # last_updated: <integer>
          # name_encoding: <value in [printable, utf8]>
          # password: <list or string>
          # private_key: <string>
          # private_key_retain: <value in [disable, enable]>
          # range: <value in [global, vdom]>
          # scep_password: <list or string>
          # scep_url: <string>
          # source: <value in [factory, user, bundle, ...]>
          # source_ip: <string>
          # state: <string>
          # tmp_cert_file: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/local'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_certificate_local': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'acme-ca-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'acme-domain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'acme-email': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'acme-renew-window': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'acme-rsa-key-size': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'int'},
                'auto-regenerate-days': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'auto-regenerate-days-warning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'ca-identifier': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'certificate': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cmp-path': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cmp-regeneration-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['keyupate', 'renewal'], 'type': 'str'},
                'cmp-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'cmp-server-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'comments': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'csr': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'enroll-protocol': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['none', 'scep', 'cmpv2', 'acme2', 'est'], 'type': 'str'},
                'est-ca-id': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'est-client-cert': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'est-http-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'est-http-username': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'est-server': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'est-server-cert': {'v_range': [['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'est-srp-password': {'v_range': [['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'est-srp-username': {'v_range': [['7.4.3', '']], 'type': 'str'},
                'ike-localid': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ike-localid-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['fqdn', 'asn1dn'], 'type': 'str'},
                'last-updated': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'},
                'name-encoding': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['printable', 'utf8'], 'type': 'str'},
                'password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'private-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                'private-key-retain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'range': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['global', 'vdom'], 'type': 'str'},
                'scep-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'scep-url': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'source': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['factory', 'user', 'bundle', 'fortiguard'], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'state': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'tmp-cert-file': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_certificate_local'),
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
