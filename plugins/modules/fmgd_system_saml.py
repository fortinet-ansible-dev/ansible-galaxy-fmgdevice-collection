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
module: fmgd_system_saml
short_description: Global settings for SAML authentication.
version_added: "1.0.0"
extends_documentation_fragment:
  - fortinet.fmgdevice.general
  - fortinet.fmgdevice.general.partial_crud
options:
  device:
    description: The parameter (device) in requested url.
    type: str
    required: true
  system_saml:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      artifact_resolution_url:
        aliases: ['artifact-resolution-url']
        type: str
        description: SP artifact resolution URL.
      binding_protocol:
        aliases: ['binding-protocol']
        type: str
        description: IdP Binding protocol.
        choices: ['post', 'redirect']
      cert:
        type: list
        elements: str
        description: Certificate to sign SAML messages.
      default_login_page:
        aliases: ['default-login-page']
        type: str
        description: Choose default login page.
        choices: ['normal', 'sso']
      default_profile:
        aliases: ['default-profile']
        type: list
        elements: str
        description: Default profile for new SSO admin.
      entity_id:
        aliases: ['entity-id']
        type: str
        description: SP entity ID.
      idp_artifact_resolution_url:
        aliases: ['idp-artifact-resolution-url']
        type: str
        description: IDP artifact resolution URL.
      idp_cert:
        aliases: ['idp-cert']
        type: list
        elements: str
        description: IDP certificate name.
      idp_entity_id:
        aliases: ['idp-entity-id']
        type: str
        description: IDP entity ID.
      idp_single_logout_url:
        aliases: ['idp-single-logout-url']
        type: str
        description: IDP single logout URL.
      idp_single_sign_on_url:
        aliases: ['idp-single-sign-on-url']
        type: str
        description: IDP single sign-on URL.
      life:
        type: int
        description: Length of the range of time when the assertion is valid
      portal_url:
        aliases: ['portal-url']
        type: str
        description: Portal url.
      role:
        type: str
        description: SAML role.
        choices: ['IDP', 'SP', 'identity-provider', 'service-provider']
      server_address:
        aliases: ['server-address']
        type: str
        description: Server address.
      service_providers:
        aliases: ['service-providers']
        type: list
        elements: dict
        description: Service providers.
        suboptions:
          assertion_attributes:
            aliases: ['assertion-attributes']
            type: list
            elements: dict
            description: Assertion attributes.
            suboptions:
              name:
                type: str
                description: Name.
              type:
                type: str
                description: Type.
                choices: ['username', 'email', 'privilege', 'profile-name']
          idp_artifact_resolution_url:
            aliases: ['idp-artifact-resolution-url']
            type: str
            description: IDP artifact resolution URL.
          idp_entity_id:
            aliases: ['idp-entity-id']
            type: str
            description: Idp entity id.
          idp_single_logout_url:
            aliases: ['idp-single-logout-url']
            type: str
            description: Idp single logout url.
          idp_single_sign_on_url:
            aliases: ['idp-single-sign-on-url']
            type: str
            description: Idp single sign on url.
          name:
            type: str
            description: Name.
          prefix:
            type: str
            description: Prefix.
          sp_artifact_resolution_url:
            aliases: ['sp-artifact-resolution-url']
            type: str
            description: SP artifact resolution URL.
          sp_binding_protocol:
            aliases: ['sp-binding-protocol']
            type: str
            description: SP binding protocol.
            choices: ['post', 'redirect']
          sp_cert:
            aliases: ['sp-cert']
            type: list
            elements: str
            description: SP certificate name.
          sp_entity_id:
            aliases: ['sp-entity-id']
            type: str
            description: SP entity ID.
          sp_portal_url:
            aliases: ['sp-portal-url']
            type: str
            description: SP portal URL.
          sp_single_logout_url:
            aliases: ['sp-single-logout-url']
            type: str
            description: SP single logout URL.
          sp_single_sign_on_url:
            aliases: ['sp-single-sign-on-url']
            type: str
            description: SP single sign-on URL.
      single_logout_url:
        aliases: ['single-logout-url']
        type: str
        description: Single logout url.
      single_sign_on_url:
        aliases: ['single-sign-on-url']
        type: str
        description: Single sign on url.
      status:
        type: str
        description: Enable/disable SAML authentication
        choices: ['disable', 'enable']
      tolerance:
        type: int
        description: Tolerance to the range of time when the assertion is valid
      require_signed_resp_and_asrt:
        aliases: ['require-signed-resp-and-asrt']
        type: str
        description: Require both response and assertion from IDP to be signed when FGT acts as SP
        choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Global settings for SAML authentication.
      fortinet.fmgdevice.fmgd_system_saml:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        system_saml:
          # artifact_resolution_url: <string>
          # binding_protocol: <value in [post, redirect]>
          # cert: <list or string>
          # default_login_page: <value in [normal, sso]>
          # default_profile: <list or string>
          # entity_id: <string>
          # idp_artifact_resolution_url: <string>
          # idp_cert: <list or string>
          # idp_entity_id: <string>
          # idp_single_logout_url: <string>
          # idp_single_sign_on_url: <string>
          # life: <integer>
          # portal_url: <string>
          # role: <value in [IDP, SP, identity-provider, ...]>
          # server_address: <string>
          # service_providers:
          #   - assertion_attributes:
          #       - name: <string>
          #         type: <value in [username, email, privilege, ...]>
          #     idp_artifact_resolution_url: <string>
          #     idp_entity_id: <string>
          #     idp_single_logout_url: <string>
          #     idp_single_sign_on_url: <string>
          #     name: <string>
          #     prefix: <string>
          #     sp_artifact_resolution_url: <string>
          #     sp_binding_protocol: <value in [post, redirect]>
          #     sp_cert: <list or string>
          #     sp_entity_id: <string>
          #     sp_portal_url: <string>
          #     sp_single_logout_url: <string>
          #     sp_single_sign_on_url: <string>
          # single_logout_url: <string>
          # single_sign_on_url: <string>
          # status: <value in [disable, enable]>
          # tolerance: <integer>
          # require_signed_resp_and_asrt: <value in [disable, enable]>
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
        '/pm/config/device/{device}/global/system/saml'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_saml': {
            'type': 'dict', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
            'options': {
                'artifact-resolution-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'binding-protocol': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['post', 'redirect'], 'type': 'str'},
                'cert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'default-login-page': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['normal', 'sso'], 'type': 'str'},
                'default-profile': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'entity-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'idp-artifact-resolution-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'idp-cert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                'idp-entity-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'idp-single-logout-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'idp-single-sign-on-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'life': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'portal-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'role': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'choices': ['IDP', 'SP', 'identity-provider', 'service-provider'],
                    'type': 'str'
                },
                'server-address': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'service-providers': {
                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                    'type': 'list',
                    'options': {
                        'assertion-attributes': {
                            'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                                'type': {
                                    'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']],
                                    'choices': ['username', 'email', 'privilege', 'profile-name'],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'idp-artifact-resolution-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'idp-entity-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'idp-single-logout-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'idp-single-sign-on-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'prefix': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'sp-artifact-resolution-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'sp-binding-protocol': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['post', 'redirect'], 'type': 'str'},
                        'sp-cert': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'list', 'elements': 'str'},
                        'sp-entity-id': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'sp-portal-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'sp-single-logout-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                        'sp-single-sign-on-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'single-logout-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'single-sign-on-url': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'str'},
                'status': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tolerance': {'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']], 'type': 'int'},
                'require-signed-resp-and-asrt': {'v_range': [['7.4.9', '7.4.11'], ['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_saml'),
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
