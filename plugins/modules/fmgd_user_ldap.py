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
module: fmgd_user_ldap
short_description: Configure LDAP server entries.
version_added: "1.1.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.full_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  vdom:
    description: The parameter (vdom) in requested url.
    type: str
    required: true
  user_ldap:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      account_key_filter:
        aliases: ['account-key-filter']
        type: str
        description: Account key filter, using the UPN as the search filter.
      account_key_processing:
        aliases: ['account-key-processing']
        type: str
        description: Account key processing operation.
        choices: ['same', 'strip']
      account_key_upn_san:
        aliases: ['account-key-upn-san']
        type: str
        description: Define SAN in certificate for user principle name matching.
        choices: ['othername', 'rfc822name', 'dnsname']
      antiphish:
        type: str
        description: Enable/disable AntiPhishing credential backend.
        choices: ['disable', 'enable']
      ca_cert:
        aliases: ['ca-cert']
        type: list
        elements: str
        description: CA certificate name.
      client_cert:
        aliases: ['client-cert']
        type: list
        elements: str
        description: Client certificate name.
      client_cert_auth:
        aliases: ['client-cert-auth']
        type: str
        description: Enable/disable using client certificate for TLS authentication.
        choices: ['disable', 'enable']
      cnid:
        type: str
        description: Common name identifier for the LDAP server.
      dn:
        type: str
        description: Distinguished name used to look up entries on the LDAP server.
      dynamic_mapping:
        type: list
        elements: dict
        description: Dynamic mapping.
        suboptions:
          _scope:
            type: list
            elements: dict
            description: Scope.
            suboptions:
              name:
                type: str
                description: Name.
              vdom:
                type: str
                description: Vdom.
          account_key_cert_field:
            aliases: ['account-key-cert-field']
            type: str
            description: Define subject identity field in certificate for user access right checking.
            choices: ['othername', 'rfc822name', 'dnsname', 'cn']
          account_key_filter:
            aliases: ['account-key-filter']
            type: str
            description: Account key filter, using the UPN as the search filter.
          account_key_name:
            aliases: ['account-key-name']
            type: str
            description: Account key name, using the UPN as the search filter.
          account_key_processing:
            aliases: ['account-key-processing']
            type: str
            description: Account key processing operation.
            choices: ['same', 'strip']
          account_key_upn_san:
            aliases: ['account-key-upn-san']
            type: str
            description: Define SAN in certificate for user principle name matching.
            choices: ['othername', 'rfc822name', 'dnsname']
          antiphish:
            type: str
            description: Enable/disable AntiPhishing credential backend.
            choices: ['disable', 'enable']
          ca_cert:
            aliases: ['ca-cert']
            type: str
            description: CA certificate name.
          client_cert:
            aliases: ['client-cert']
            type: list
            elements: str
            description: Client certificate name.
          client_cert_auth:
            aliases: ['client-cert-auth']
            type: str
            description: Enable/disable using client certificate for TLS authentication.
            choices: ['disable', 'enable']
          cnid:
            type: str
            description: Common name identifier for the LDAP server.
          dn:
            type: str
            description: Distinguished name used to look up entries on the LDAP server.
          filter:
            type: str
            description: Filter.
          group:
            type: str
            description: Group.
          group_filter:
            aliases: ['group-filter']
            type: str
            description: Filter used for group matching.
          group_member_check:
            aliases: ['group-member-check']
            type: str
            description: Group member checking methods.
            choices: ['user-attr', 'group-object', 'posix-group-object']
          group_object_filter:
            aliases: ['group-object-filter']
            type: str
            description: Filter used for group searching.
          group_object_search_base:
            aliases: ['group-object-search-base']
            type: str
            description: Group object search base.
          group_search_base:
            aliases: ['group-search-base']
            type: str
            description: Search base used for group searching.
          interface:
            type: list
            elements: str
            description: Specify outgoing interface to reach server.
          interface_select_method:
            aliases: ['interface-select-method']
            type: str
            description: Specify how to select outgoing interface to reach server.
            choices: ['auto', 'sdwan', 'specify']
          max_connections:
            aliases: ['max-connections']
            type: int
            description: Max connections.
          member_attr:
            aliases: ['member-attr']
            type: str
            description: Name of attribute from which to get group membership.
          obtain_user_info:
            aliases: ['obtain-user-info']
            type: str
            description: Enable/disable obtaining of user information.
            choices: ['disable', 'enable']
          password:
            type: list
            elements: str
            description: Password for initial binding.
          password_attr:
            aliases: ['password-attr']
            type: str
            description: Name of attribute to get password hash.
          password_expiry_warning:
            aliases: ['password-expiry-warning']
            type: str
            description: Enable/disable password expiry warnings.
            choices: ['disable', 'enable']
          password_renewal:
            aliases: ['password-renewal']
            type: str
            description: Enable/disable online password renewal.
            choices: ['disable', 'enable']
          port:
            type: int
            description: Port to be used for communication with the LDAP server
          retrieve_protection_profile:
            aliases: ['retrieve-protection-profile']
            type: str
            description: Retrieve protection profile.
          search_type:
            aliases: ['search-type']
            type: list
            elements: str
            description: Search type.
            choices: ['recursive', 'nested']
          secondary_server:
            aliases: ['secondary-server']
            type: str
            description: Secondary LDAP server CN domain name or IP.
          secure:
            type: str
            description: Port to be used for authentication.
            choices: ['disable', 'starttls', 'ldaps']
          server:
            type: str
            description: LDAP server CN domain name or IP.
          server_identity_check:
            aliases: ['server-identity-check']
            type: str
            description: Enable/disable LDAP server identity check
            choices: ['disable', 'enable']
          source_ip:
            aliases: ['source-ip']
            type: str
            description: FortiGate IP address to be used for communication with the LDAP server.
          source_port:
            aliases: ['source-port']
            type: int
            description: Source port to be used for communication with the LDAP server.
          ssl_max_proto_version:
            aliases: ['ssl-max-proto-version']
            type: str
            description: Ssl max proto version.
            choices: ['TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3']
          ssl_min_proto_version:
            aliases: ['ssl-min-proto-version']
            type: str
            description: Minimum supported protocol version for SSL/TLS connections
            choices: ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3']
          status_ttl:
            aliases: ['status-ttl']
            type: int
            description: Time for which server reachability is cached so that when a server is unreachable, it will not be retried for at least this pe...
          tertiary_server:
            aliases: ['tertiary-server']
            type: str
            description: Tertiary LDAP server CN domain name or IP.
          two_factor:
            aliases: ['two-factor']
            type: str
            description: Enable/disable two-factor authentication.
            choices: ['disable', 'fortitoken-cloud']
          two_factor_authentication:
            aliases: ['two-factor-authentication']
            type: str
            description: Authentication method by FortiToken Cloud.
            choices: ['fortitoken', 'email', 'sms']
          two_factor_filter:
            aliases: ['two-factor-filter']
            type: str
            description: Filter used to synchronize users to FortiToken Cloud.
          two_factor_notification:
            aliases: ['two-factor-notification']
            type: str
            description: Notification method for user activation by FortiToken Cloud.
            choices: ['email', 'sms']
          type:
            type: str
            description: Authentication type for LDAP searches.
            choices: ['simple', 'anonymous', 'regular']
          user_info_exchange_server:
            aliases: ['user-info-exchange-server']
            type: list
            elements: str
            description: MS Exchange server from which to fetch user information.
          username:
            type: str
            description: Username
          source_ip_interface:
            aliases: ['source-ip-interface']
            type: list
            elements: str
            description: Source interface for communication with the LDAP server.
          validate_server_certificate:
            aliases: ['validate-server-certificate']
            type: str
            description: Validate server certificate.
            choices: ['disable', 'enable']
          vrf_select:
            aliases: ['vrf-select']
            type: int
            description: VRF ID used for connection to server.
          fabric_force_sync:
            aliases: ['fabric-force-sync']
            type: str
            description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
            choices: ['disable', 'enable']
          fabric_object:
            aliases: ['fabric-object']
            type: str
            description: Security Fabric global object setting.
            choices: ['disable', 'enable']
          fabric_object_source:
            aliases: ['fabric-object-source']
            type: str
            description: Source of truth for fabric object.
            choices: ['member', 'local', 'root']
          uuid:
            type: str
            description: Universally Unique Identifier
      group_filter:
        aliases: ['group-filter']
        type: str
        description: Filter used for group matching.
      group_member_check:
        aliases: ['group-member-check']
        type: str
        description: Group member checking methods.
        choices: ['user-attr', 'group-object', 'posix-group-object']
      group_object_filter:
        aliases: ['group-object-filter']
        type: str
        description: Filter used for group searching.
      group_search_base:
        aliases: ['group-search-base']
        type: str
        description: Search base used for group searching.
      interface:
        type: list
        elements: str
        description: Specify outgoing interface to reach server.
      interface_select_method:
        aliases: ['interface-select-method']
        type: str
        description: Specify how to select outgoing interface to reach server.
        choices: ['auto', 'sdwan', 'specify']
      max_connections:
        aliases: ['max-connections']
        type: int
        description: Max connections.
      member_attr:
        aliases: ['member-attr']
        type: str
        description: Name of attribute from which to get group membership.
      name:
        type: str
        description: LDAP server entry name.
        required: true
      obtain_user_info:
        aliases: ['obtain-user-info']
        type: str
        description: Enable/disable obtaining of user information.
        choices: ['disable', 'enable']
      password:
        type: list
        elements: str
        description: Password for initial binding.
      password_attr:
        aliases: ['password-attr']
        type: str
        description: Name of attribute to get password hash.
      password_expiry_warning:
        aliases: ['password-expiry-warning']
        type: str
        description: Enable/disable password expiry warnings.
        choices: ['disable', 'enable']
      password_renewal:
        aliases: ['password-renewal']
        type: str
        description: Enable/disable online password renewal.
        choices: ['disable', 'enable']
      port:
        type: int
        description: Port to be used for communication with the LDAP server
      search_type:
        aliases: ['search-type']
        type: list
        elements: str
        description: Search type.
        choices: ['recursive']
      secondary_server:
        aliases: ['secondary-server']
        type: str
        description: Secondary LDAP server CN domain name or IP.
      secure:
        type: str
        description: Port to be used for authentication.
        choices: ['disable', 'starttls', 'ldaps']
      server:
        type: str
        description: LDAP server CN domain name or IP.
      server_identity_check:
        aliases: ['server-identity-check']
        type: str
        description: Enable/disable LDAP server identity check
        choices: ['disable', 'enable']
      source_ip:
        aliases: ['source-ip']
        type: str
        description: FortiGate IP address to be used for communication with the LDAP server.
      source_port:
        aliases: ['source-port']
        type: int
        description: Source port to be used for communication with the LDAP server.
      ssl_max_proto_version:
        aliases: ['ssl-max-proto-version']
        type: str
        description: Ssl max proto version.
        choices: ['TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3']
      ssl_min_proto_version:
        aliases: ['ssl-min-proto-version']
        type: str
        description: Minimum supported protocol version for SSL/TLS connections
        choices: ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3']
      tertiary_server:
        aliases: ['tertiary-server']
        type: str
        description: Tertiary LDAP server CN domain name or IP.
      two_factor:
        aliases: ['two-factor']
        type: str
        description: Enable/disable two-factor authentication.
        choices: ['disable', 'fortitoken-cloud']
      two_factor_authentication:
        aliases: ['two-factor-authentication']
        type: str
        description: Authentication method by FortiToken Cloud.
        choices: ['fortitoken', 'email', 'sms']
      two_factor_filter:
        aliases: ['two-factor-filter']
        type: str
        description: Filter used to synchronize users to FortiToken Cloud.
      two_factor_notification:
        aliases: ['two-factor-notification']
        type: str
        description: Notification method for user activation by FortiToken Cloud.
        choices: ['email', 'sms']
      type:
        type: str
        description: Authentication type for LDAP searches.
        choices: ['simple', 'anonymous', 'regular']
      user_info_exchange_server:
        aliases: ['user-info-exchange-server']
        type: list
        elements: str
        description: MS Exchange server from which to fetch user information.
      username:
        type: str
        description: Username
      status_ttl:
        aliases: ['status-ttl']
        type: int
        description: Time for which server reachability is cached so that when a server is unreachable, it will not be retried for at least this period...
      account_key_cert_field:
        aliases: ['account-key-cert-field']
        type: str
        description: Define subject identity field in certificate for user access right checking.
        choices: ['othername', 'rfc822name', 'dnsname', 'cn']
      account_key_name:
        aliases: ['account-key-name']
        type: str
        description: Account key name, using the UPN as the search filter.
      validate_server_certificate:
        aliases: ['validate-server-certificate']
        type: str
        description: Validate server certificate.
        choices: ['disable', 'enable']
      source_ip_interface:
        aliases: ['source-ip-interface']
        type: list
        elements: str
        description: Source interface for communication with the LDAP server.
      vrf_select:
        aliases: ['vrf-select']
        type: int
        description: VRF ID used for connection to server.
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      uuid:
        type: str
        description: Universally Unique Identifier
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure LDAP server entries.
      fortinet.fmgdevice.fmgd_user_ldap:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        user_ldap:
          name: "your value" # Required variable, string
          # account_key_filter: <string>
          # account_key_processing: <value in [same, strip]>
          # account_key_upn_san: <value in [othername, rfc822name, dnsname]>
          # antiphish: <value in [disable, enable]>
          # ca_cert: <list or string>
          # client_cert: <list or string>
          # client_cert_auth: <value in [disable, enable]>
          # cnid: <string>
          # dn: <string>
          # dynamic_mapping:
          #   - _scope:
          #       - name: <string>
          #         vdom: <string>
          #     account_key_cert_field: <value in [othername, rfc822name, dnsname, ...]>
          #     account_key_filter: <string>
          #     account_key_name: <string>
          #     account_key_processing: <value in [same, strip]>
          #     account_key_upn_san: <value in [othername, rfc822name, dnsname]>
          #     antiphish: <value in [disable, enable]>
          #     ca_cert: <string>
          #     client_cert: <list or string>
          #     client_cert_auth: <value in [disable, enable]>
          #     cnid: <string>
          #     dn: <string>
          #     filter: <string>
          #     group: <string>
          #     group_filter: <string>
          #     group_member_check: <value in [user-attr, group-object, posix-group-object]>
          #     group_object_filter: <string>
          #     group_object_search_base: <string>
          #     group_search_base: <string>
          #     interface: <list or string>
          #     interface_select_method: <value in [auto, sdwan, specify]>
          #     max_connections: <integer>
          #     member_attr: <string>
          #     obtain_user_info: <value in [disable, enable]>
          #     password: <list or string>
          #     password_attr: <string>
          #     password_expiry_warning: <value in [disable, enable]>
          #     password_renewal: <value in [disable, enable]>
          #     port: <integer>
          #     retrieve_protection_profile: <string>
          #     search_type: ["recursive", "nested"]
          #     secondary_server: <string>
          #     secure: <value in [disable, starttls, ldaps]>
          #     server: <string>
          #     server_identity_check: <value in [disable, enable]>
          #     source_ip: <string>
          #     source_port: <integer>
          #     ssl_max_proto_version: <value in [TLSv1-1, TLSv1-2, SSLv3, ...]>
          #     ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          #     status_ttl: <integer>
          #     tertiary_server: <string>
          #     two_factor: <value in [disable, fortitoken-cloud]>
          #     two_factor_authentication: <value in [fortitoken, email, sms]>
          #     two_factor_filter: <string>
          #     two_factor_notification: <value in [email, sms]>
          #     type: <value in [simple, anonymous, regular]>
          #     user_info_exchange_server: <list or string>
          #     username: <string>
          #     source_ip_interface: <list or string>
          #     validate_server_certificate: <value in [disable, enable]>
          #     vrf_select: <integer>
          #     fabric_force_sync: <value in [disable, enable]>
          #     fabric_object: <value in [disable, enable]>
          #     fabric_object_source: <value in [member, local, root]>
          #     uuid: <string>
          # group_filter: <string>
          # group_member_check: <value in [user-attr, group-object, posix-group-object]>
          # group_object_filter: <string>
          # group_search_base: <string>
          # interface: <list or string>
          # interface_select_method: <value in [auto, sdwan, specify]>
          # max_connections: <integer>
          # member_attr: <string>
          # obtain_user_info: <value in [disable, enable]>
          # password: <list or string>
          # password_attr: <string>
          # password_expiry_warning: <value in [disable, enable]>
          # password_renewal: <value in [disable, enable]>
          # port: <integer>
          # search_type: ["recursive"]
          # secondary_server: <string>
          # secure: <value in [disable, starttls, ldaps]>
          # server: <string>
          # server_identity_check: <value in [disable, enable]>
          # source_ip: <string>
          # source_port: <integer>
          # ssl_max_proto_version: <value in [TLSv1-1, TLSv1-2, SSLv3, ...]>
          # ssl_min_proto_version: <value in [default, TLSv1, TLSv1-1, ...]>
          # tertiary_server: <string>
          # two_factor: <value in [disable, fortitoken-cloud]>
          # two_factor_authentication: <value in [fortitoken, email, sms]>
          # two_factor_filter: <string>
          # two_factor_notification: <value in [email, sms]>
          # type: <value in [simple, anonymous, regular]>
          # user_info_exchange_server: <list or string>
          # username: <string>
          # status_ttl: <integer>
          # account_key_cert_field: <value in [othername, rfc822name, dnsname, ...]>
          # account_key_name: <string>
          # validate_server_certificate: <value in [disable, enable]>
          # source_ip_interface: <list or string>
          # vrf_select: <integer>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # uuid: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/user/ldap'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'user_ldap': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                'account-key-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'account-key-processing': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['same', 'strip'], 'type': 'str'},
                'account-key-upn-san': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['othername', 'rfc822name', 'dnsname'], 'type': 'str'},
                'antiphish': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ca-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'client-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'client-cert-auth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cnid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'account-key-cert-field': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['othername', 'rfc822name', 'dnsname', 'cn'],
                            'type': 'str'
                        },
                        'account-key-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                        'account-key-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                        'account-key-processing': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['same', 'strip'], 'type': 'str'},
                        'account-key-upn-san': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['othername', 'rfc822name', 'dnsname'],
                            'type': 'str'
                        },
                        'antiphish': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ca-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'client-cert': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'client-cert-auth': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'cnid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'dn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'group-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'group-member-check': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['user-attr', 'group-object', 'posix-group-object'],
                            'type': 'str'
                        },
                        'group-object-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'group-object-search-base': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'group-search-base': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'interface-select-method': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['auto', 'sdwan', 'specify'],
                            'type': 'str'
                        },
                        'max-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'member-attr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'obtain-user-info': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                        'password-attr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                        'password-expiry-warning': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'password-renewal': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'retrieve-protection-profile': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'search-type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'choices': ['recursive', 'nested'],
                            'elements': 'str'
                        },
                        'secondary-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'secure': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'starttls', 'ldaps'], 'type': 'str'},
                        'server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'server-identity-check': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'source-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'source-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'ssl-max-proto-version': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                            'type': 'str'
                        },
                        'ssl-min-proto-version': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                            'type': 'str'
                        },
                        'status-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'tertiary-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'two-factor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'fortitoken-cloud'], 'type': 'str'},
                        'two-factor-authentication': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['fortitoken', 'email', 'sms'],
                            'type': 'str'
                        },
                        'two-factor-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'two-factor-notification': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['email', 'sms'], 'type': 'str'},
                        'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['simple', 'anonymous', 'regular'], 'type': 'str'},
                        'user-info-exchange-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'source-ip-interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'validate-server-certificate': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'},
                        'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                        'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'group-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'group-member-check': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['user-attr', 'group-object', 'posix-group-object'],
                    'type': 'str'
                },
                'group-object-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'group-search-base': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface-select-method': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['auto', 'sdwan', 'specify'], 'type': 'str'},
                'max-connections': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'member-attr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'obtain-user-info': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'password-attr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'password-expiry-warning': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'password-renewal': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'search-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'choices': ['recursive'], 'elements': 'str'},
                'secondary-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'secure': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'starttls', 'ldaps'], 'type': 'str'},
                'server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'server-identity-check': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'source-port': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'ssl-max-proto-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1', 'TLSv1-3'],
                    'type': 'str'
                },
                'ssl-min-proto-version': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['default', 'TLSv1', 'TLSv1-1', 'TLSv1-2', 'SSLv3', 'TLSv1-3'],
                    'type': 'str'
                },
                'tertiary-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'two-factor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'fortitoken-cloud'], 'type': 'str'},
                'two-factor-authentication': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['fortitoken', 'email', 'sms'], 'type': 'str'},
                'two-factor-filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'two-factor-notification': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['email', 'sms'], 'type': 'str'},
                'type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['simple', 'anonymous', 'regular'], 'type': 'str'},
                'user-info-exchange-server': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'username': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'status-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'account-key-cert-field': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['othername', 'rfc822name', 'dnsname', 'cn'],
                    'type': 'str'
                },
                'account-key-name': {'v_range': [['7.4.8', '7.4.11']], 'no_log': True, 'type': 'str'},
                'validate-server-certificate': {'v_range': [['7.6.4', '7.6.4']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'source-ip-interface': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'vrf-select': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'uuid': {'v_range': [['8.0.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_ldap'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('full crud', module_arg_spec, urls_list,
                       'name', 'data', module, connection)
    fmgd.process_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
