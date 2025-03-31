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
module: fmgd_vpn_certificate_setting
short_description: VPN certificate setting.
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
    vpn_certificate_setting:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            cert_expire_warning:
                aliases: ['cert-expire-warning']
                type: int
                description: Number of days before a certificate expires to send a warning.
            certname_dsa1024:
                aliases: ['certname-dsa1024']
                type: list
                elements: str
                description: 1024 bit DSA key certificate for re-signing server certificates for SSL inspection.
            certname_dsa2048:
                aliases: ['certname-dsa2048']
                type: list
                elements: str
                description: 2048 bit DSA key certificate for re-signing server certificates for SSL inspection.
            certname_ecdsa256:
                aliases: ['certname-ecdsa256']
                type: list
                elements: str
                description: 256 bit ECDSA key certificate for re-signing server certificates for SSL inspection.
            certname_ecdsa384:
                aliases: ['certname-ecdsa384']
                type: list
                elements: str
                description: 384 bit ECDSA key certificate for re-signing server certificates for SSL inspection.
            certname_ecdsa521:
                aliases: ['certname-ecdsa521']
                type: list
                elements: str
                description: 521 bit ECDSA key certificate for re-signing server certificates for SSL inspection.
            certname_ed25519:
                aliases: ['certname-ed25519']
                type: list
                elements: str
                description: 253 bit EdDSA key certificate for re-signing server certificates for SSL inspection.
            certname_ed448:
                aliases: ['certname-ed448']
                type: list
                elements: str
                description: 456 bit EdDSA key certificate for re-signing server certificates for SSL inspection.
            certname_rsa1024:
                aliases: ['certname-rsa1024']
                type: list
                elements: str
                description: 1024 bit RSA key certificate for re-signing server certificates for SSL inspection.
            certname_rsa2048:
                aliases: ['certname-rsa2048']
                type: list
                elements: str
                description: 2048 bit RSA key certificate for re-signing server certificates for SSL inspection.
            certname_rsa4096:
                aliases: ['certname-rsa4096']
                type: list
                elements: str
                description: 4096 bit RSA key certificate for re-signing server certificates for SSL inspection.
            check_ca_cert:
                aliases: ['check-ca-cert']
                type: str
                description: Enable/disable verification of the user certificate and pass authentication if any CA in the chain is trusted
                choices:
                    - 'disable'
                    - 'enable'
            check_ca_chain:
                aliases: ['check-ca-chain']
                type: str
                description: Enable/disable verification of the entire certificate chain and pass authentication only if the chain is complete and all ...
                choices:
                    - 'disable'
                    - 'enable'
            cmp_key_usage_checking:
                aliases: ['cmp-key-usage-checking']
                type: str
                description: Enable/disable server certificate key usage checking in CMP mode
                choices:
                    - 'disable'
                    - 'enable'
            cmp_save_extra_certs:
                aliases: ['cmp-save-extra-certs']
                type: str
                description: Enable/disable saving extra certificates in CMP mode
                choices:
                    - 'disable'
                    - 'enable'
            cn_allow_multi:
                aliases: ['cn-allow-multi']
                type: str
                description: When searching for a matching certificate, allow multiple CN fields in certificate subject name
                choices:
                    - 'disable'
                    - 'enable'
            cn_match:
                aliases: ['cn-match']
                type: str
                description: When searching for a matching certificate, control how to do CN value matching with certificate subject name
                choices:
                    - 'substring'
                    - 'value'
            crl_verification:
                aliases: ['crl-verification']
                type: dict
                description: Crl verification.
                suboptions:
                    chain_crl_absence:
                        aliases: ['chain-crl-absence']
                        type: str
                        description: CRL verification option when CRL of any certificate in chain is absent
                        choices:
                            - 'ignore'
                            - 'revoke'
                    expiry:
                        type: str
                        description: CRL verification option when CRL is expired
                        choices:
                            - 'ignore'
                            - 'revoke'
                    leaf_crl_absence:
                        aliases: ['leaf-crl-absence']
                        type: str
                        description: CRL verification option when leaf CRL is absent
                        choices:
                            - 'ignore'
                            - 'revoke'
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
            ocsp_default_server:
                aliases: ['ocsp-default-server']
                type: list
                elements: str
                description: Default OCSP server.
            ocsp_option:
                aliases: ['ocsp-option']
                type: str
                description: Specify whether the OCSP URL is from certificate or configured OCSP server.
                choices:
                    - 'certificate'
                    - 'server'
            ocsp_status:
                aliases: ['ocsp-status']
                type: str
                description: Enable/disable receiving certificates using the OCSP.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'mandatory'
            proxy:
                type: str
                description: Proxy server FQDN or IP for OCSP/CA queries during certificate verification.
            proxy_password:
                aliases: ['proxy-password']
                type: list
                elements: str
                description: Proxy server password.
            proxy_port:
                aliases: ['proxy-port']
                type: int
                description: Proxy server port
            proxy_username:
                aliases: ['proxy-username']
                type: str
                description: Proxy server user name.
            source_ip:
                aliases: ['source-ip']
                type: str
                description: Source IP address for dynamic AIA and OCSP queries.
            ssl_min_proto_version:
                aliases: ['ssl-min-proto-version']
                type: str
                description: Minimum supported protocol version for SSL/TLS connections
                choices:
                    - 'default'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'SSLv3'
                    - 'TLSv1-3'
            strict_ocsp_check:
                aliases: ['strict-ocsp-check']
                type: str
                description: Enable/disable strict mode OCSP checking.
                choices:
                    - 'disable'
                    - 'enable'
            subject_match:
                aliases: ['subject-match']
                type: str
                description: When searching for a matching certificate, control how to do RDN value matching with certificate subject name
                choices:
                    - 'substring'
                    - 'value'
            subject_set:
                aliases: ['subject-set']
                type: str
                description: When searching for a matching certificate, control how to do RDN set matching with certificate subject name
                choices:
                    - 'subset'
                    - 'superset'
            ssl_ocsp_source_ip:
                aliases: ['ssl-ocsp-source-ip']
                type: str
                description: Source IP address to use to communicate with the OCSP server.
            strict_crl_check:
                aliases: ['strict-crl-check']
                type: str
                description: Enable/disable strict mode CRL checking.
                choices:
                    - 'disable'
                    - 'enable'
            vrf_select:
                aliases: ['vrf-select']
                type: int
                description: VRF ID used for connection to server.
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
    - name: VPN certificate setting.
      fortinet.fmgdevice.fmgd_vpn_certificate_setting:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        vpn_certificate_setting:
          # cert_expire_warning: <integer>
          # certname_dsa1024: <list or string>
          # certname_dsa2048: <list or string>
          # certname_ecdsa256: <list or string>
          # certname_ecdsa384: <list or string>
          # certname_ecdsa521: <list or string>
          # certname_ed25519: <list or string>
          # certname_ed448: <list or string>
          # certname_rsa1024: <list or string>
          # certname_rsa2048: <list or string>
          # certname_rsa4096: <list or string>
          # check_ca_cert: <value in [disable, enable]>
          # check_ca_chain: <value in [disable, enable]>
          # cmp_key_usage_checking: <value in [disable, enable]>
          # cmp_save_extra_certs: <value in [disable, enable]>
          # cn_allow_multi: <value in [disable, enable]>
          # cn_match: <value in [substring, value]>
          # crl_verification:
          #   chain_crl_absence: <value in [ignore, revoke]>
          #   expiry: <value in [ignore, revoke]>
          #   leaf_crl_absence: <value in [ignore, revoke]>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # ocsp_default_server: <list or string>
          # ocsp_option: <value in [certificate, server]>
          # ocsp_status: <value in [disable, enable, mandatory]>
          # proxy: <string>
          # proxy_password: <list or string>
          # proxy_port: <integer>
          # proxy_username: <string>
          # source_ip: <string>
          # ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # strict_ocsp_check: <value in [disable, enable]>
          # subject_match: <value in [substring, value]>
          # subject_set: <value in [subset, superset]>
          # ssl_ocsp_source_ip: <string>
          # strict_crl_check: <value in [disable, enable]>
          # vrf_select: <integer>
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
        '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/setting'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = None
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'vpn_certificate_setting': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'cert-expire-warning': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'certname-dsa1024': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-dsa2048': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-ecdsa256': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-ecdsa384': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-ecdsa521': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-ed25519': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-ed448': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-rsa1024': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-rsa2048': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'certname-rsa4096': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'check-ca-cert': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'check-ca-chain': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cmp-key-usage-checking': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cmp-save-extra-certs': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cn-allow-multi': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cn-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['substring', 'value'], 'type': 'str'},
                'crl-verification': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'chain-crl-absence': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ignore', 'revoke'], 'type': 'str'},
                        'expiry': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ignore', 'revoke'], 'type': 'str'},
                        'leaf-crl-absence': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['ignore', 'revoke'], 'type': 'str'}
                    }
                },
                'interface': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'ocsp-default-server': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'ocsp-option': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['certificate', 'server'], 'type': 'str'},
                'ocsp-status': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable', 'mandatory'], 'type': 'str'},
                'proxy': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'proxy-password': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'proxy-port': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'int'},
                'proxy-username': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'ssl-min-proto-version': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'strict-ocsp-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'subject-match': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['substring', 'value'], 'type': 'str'},
                'subject-set': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['subset', 'superset'], 'type': 'str'},
                'ssl-ocsp-source-ip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                'strict-crl-check': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vrf-select': {'v_range': [['7.6.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpn_certificate_setting'),
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
