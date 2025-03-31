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
module: fmgd_switchcontroller_location
short_description: Configure FortiSwitch location services.
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
    switchcontroller_location:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            address_civic:
                aliases: ['address-civic']
                type: dict
                description: Address civic.
                suboptions:
                    additional:
                        type: str
                        description: Location additional details.
                    additional_code:
                        aliases: ['additional-code']
                        type: str
                        description: Location additional code details.
                    block:
                        type: str
                        description: Location block details.
                    branch_road:
                        aliases: ['branch-road']
                        type: str
                        description: Location branch road details.
                    building:
                        type: str
                        description: Location building details.
                    city:
                        type: str
                        description: Location city details.
                    city_division:
                        aliases: ['city-division']
                        type: str
                        description: Location city division details.
                    country:
                        type: str
                        description: The two-letter ISO 3166 country code in capital ASCII letters eg.
                    country_subdivision:
                        aliases: ['country-subdivision']
                        type: str
                        description: National subdivisions
                    county:
                        type: str
                        description: County, parish, gun
                    direction:
                        type: str
                        description: Leading street direction.
                    floor:
                        type: str
                        description: Floor.
                    landmark:
                        type: str
                        description: Landmark or vanity address.
                    language:
                        type: str
                        description: Language.
                    name:
                        type: str
                        description: Name
                    number:
                        type: str
                        description: House number.
                    number_suffix:
                        aliases: ['number-suffix']
                        type: str
                        description: House number suffix.
                    parent_key:
                        aliases: ['parent-key']
                        type: str
                        description: Parent key.
                    place_type:
                        aliases: ['place-type']
                        type: str
                        description: Place type.
                    post_office_box:
                        aliases: ['post-office-box']
                        type: str
                        description: Post office box.
                    postal_community:
                        aliases: ['postal-community']
                        type: str
                        description: Postal community name.
                    primary_road:
                        aliases: ['primary-road']
                        type: str
                        description: Primary road name.
                    road_section:
                        aliases: ['road-section']
                        type: str
                        description: Road section.
                    room:
                        type: str
                        description: Room number.
                    script:
                        type: str
                        description: Script used to present the address information.
                    seat:
                        type: str
                        description: Seat number.
                    street:
                        type: str
                        description: Street.
                    street_name_post_mod:
                        aliases: ['street-name-post-mod']
                        type: str
                        description: Street name post modifier.
                    street_name_pre_mod:
                        aliases: ['street-name-pre-mod']
                        type: str
                        description: Street name pre modifier.
                    street_suffix:
                        aliases: ['street-suffix']
                        type: str
                        description: Street suffix.
                    sub_branch_road:
                        aliases: ['sub-branch-road']
                        type: str
                        description: Sub branch road name.
                    trailing_str_suffix:
                        aliases: ['trailing-str-suffix']
                        type: str
                        description: Trailing street suffix.
                    unit:
                        type: str
                        description: Unit
                    zip:
                        type: str
                        description: Postal/zip code.
            coordinates:
                type: dict
                description: Coordinates.
                suboptions:
                    altitude:
                        type: str
                        description: Plus or minus floating point number.
                    altitude_unit:
                        aliases: ['altitude-unit']
                        type: str
                        description: Configure the unit for which the altitude is to
                        choices:
                            - 'm'
                            - 'f'
                    datum:
                        type: str
                        description: WGS84, NAD83, NAD83/MLLW.
                        choices:
                            - 'WGS84'
                            - 'NAD83'
                            - 'NAD83/MLLW'
                    latitude:
                        type: str
                        description: Floating point starting with +/- or ending with
                    longitude:
                        type: str
                        description: Floating point starting with +/- or ending with
                    parent_key:
                        aliases: ['parent-key']
                        type: str
                        description: Parent key.
            elin_number:
                aliases: ['elin-number']
                type: dict
                description: Elin number.
                suboptions:
                    elin_num:
                        aliases: ['elin-num']
                        type: str
                        description: Configure ELIN callback number.
                    parent_key:
                        aliases: ['parent-key']
                        type: str
                        description: Parent key.
            name:
                type: str
                description: Unique location item name.
                required: true
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
    - name: Configure FortiSwitch location services.
      fortinet.fmgdevice.fmgd_switchcontroller_location:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_location:
          name: "your value" # Required variable, string
          # address_civic:
          #   additional: <string>
          #   additional_code: <string>
          #   block: <string>
          #   branch_road: <string>
          #   building: <string>
          #   city: <string>
          #   city_division: <string>
          #   country: <string>
          #   country_subdivision: <string>
          #   county: <string>
          #   direction: <string>
          #   floor: <string>
          #   landmark: <string>
          #   language: <string>
          #   name: <string>
          #   number: <string>
          #   number_suffix: <string>
          #   parent_key: <string>
          #   place_type: <string>
          #   post_office_box: <string>
          #   postal_community: <string>
          #   primary_road: <string>
          #   road_section: <string>
          #   room: <string>
          #   script: <string>
          #   seat: <string>
          #   street: <string>
          #   street_name_post_mod: <string>
          #   street_name_pre_mod: <string>
          #   street_suffix: <string>
          #   sub_branch_road: <string>
          #   trailing_str_suffix: <string>
          #   unit: <string>
          #   zip: <string>
          # coordinates:
          #   altitude: <string>
          #   altitude_unit: <value in [m, f]>
          #   datum: <value in [WGS84, NAD83, NAD83/MLLW]>
          #   latitude: <string>
          #   longitude: <string>
          #   parent_key: <string>
          # elin_number:
          #   elin_num: <string>
          #   parent_key: <string>
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
        '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location'
    ]
    url_params = ['device', 'vdom']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'switchcontroller_location': {
            'type': 'dict',
            'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
            'options': {
                'address-civic': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'additional': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'additional-code': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'block': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'branch-road': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'building': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'city': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'city-division': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'country': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'country-subdivision': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'county': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'direction': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'floor': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'landmark': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'language': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'number': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'number-suffix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'parent-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'},
                        'place-type': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'post-office-box': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'postal-community': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'primary-road': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'road-section': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'room': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'script': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'seat': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'street': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'street-name-post-mod': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'street-name-pre-mod': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'street-suffix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'sub-branch-road': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'trailing-str-suffix': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'zip': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'}
                    }
                },
                'coordinates': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'altitude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'altitude-unit': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['m', 'f'], 'type': 'str'},
                        'datum': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'choices': ['WGS84', 'NAD83', 'NAD83/MLLW'], 'type': 'str'},
                        'latitude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'longitude': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'parent-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'}
                    }
                },
                'elin-number': {
                    'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'elin-num': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'type': 'str'},
                        'parent-key': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'no_log': True, 'type': 'str'}
                    }
                },
                'name': {'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']], 'required': True, 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_location'),
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
