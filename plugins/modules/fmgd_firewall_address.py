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
module: fmgd_firewall_address
short_description: Configure IPv4 addresses.
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
  firewall_address:
    description: The top level parameters set.
    required: false
    type: dict
    suboptions:
      _image_base64:
        aliases: ['_image-base64']
        type: str
        description: Image base64.
      allow_routing:
        aliases: ['allow-routing']
        type: str
        description: Enable/disable use of this address in the static route configuration.
        choices: ['disable', 'enable']
      associated_interface:
        aliases: ['associated-interface']
        type: list
        elements: str
        description: Network interface associated with address.
      cache_ttl:
        aliases: ['cache-ttl']
        type: int
        description: Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds.
      clearpass_spt:
        aliases: ['clearpass-spt']
        type: str
        description: SPT
        choices: ['unknown', 'healthy', 'quarantine', 'checkup', 'infected', 'transient',
                  'transition']
      color:
        type: int
        description: Color of icon on the GUI.
      comment:
        type: str
        description: Comment.
      country:
        type: list
        elements: str
        description: IP addresses associated to a specific country.
      dirty:
        type: str
        description: To be deleted address.
        choices: ['dirty', 'clean']
      dynamic_mapping:
        type: list
        elements: dict
        description: Dynamic mapping.
        suboptions:
          _image_base64:
            aliases: ['_image-base64']
            type: str
            description: Image base64.
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
          allow_routing:
            aliases: ['allow-routing']
            type: str
            description: Enable/disable use of this address in the static route configuration.
            choices: ['disable', 'enable']
          associated_interface:
            aliases: ['associated-interface']
            type: str
            description: Network interface associated with address.
          cache_ttl:
            aliases: ['cache-ttl']
            type: int
            description: Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds.
          clearpass_spt:
            aliases: ['clearpass-spt']
            type: str
            description: SPT
            choices: ['unknown', 'healthy', 'quarantine', 'checkup', 'infected', 'transient',
                      'transition']
          color:
            type: int
            description: Color of icon on the GUI.
          comment:
            type: str
            description: Comment.
          country:
            type: list
            elements: str
            description: IP addresses associated to a specific country.
          dirty:
            type: str
            description: To be deleted address.
            choices: ['dirty', 'clean']
          end_ip:
            aliases: ['end-ip']
            type: str
            description:
              - Support meta variable
              - Final IP address
          end_mac:
            aliases: ['end-mac']
            type: str
            description: Support meta variable
          epg_name:
            aliases: ['epg-name']
            type: str
            description: Endpoint group name.
          fabric_object:
            aliases: ['fabric-object']
            type: str
            description: Security Fabric global object setting.
            choices: ['disable', 'enable']
          filter:
            type: str
            description: Match criteria filter.
          fqdn:
            type: str
            description:
              - Support meta variable
              - Fully Qualified Domain Name address.
          fsso_group:
            aliases: ['fsso-group']
            type: list
            elements: str
            description: FSSO group
          global_object:
            aliases: ['global-object']
            type: int
            description: Global object.
          hw_model:
            aliases: ['hw-model']
            type: str
            description: Dynamic address matching hardware model.
          hw_vendor:
            aliases: ['hw-vendor']
            type: str
            description: Dynamic address matching hardware vendor.
          interface:
            type: str
            description: Name of interface whose IP address is to be used.
          macaddr:
            type: list
            elements: str
            description:
              - Support meta variable
              - Multiple MAC address ranges.
          node_ip_only:
            aliases: ['node-ip-only']
            type: str
            description: Enable/disable collection of node addresses only in Kubernetes.
            choices: ['disable', 'enable']
          obj_id:
            aliases: ['obj-id']
            type: str
            description: Object ID for NSX.
          obj_tag:
            aliases: ['obj-tag']
            type: str
            description: Tag of dynamic address object.
          obj_type:
            aliases: ['obj-type']
            type: str
            description: Object type.
            choices: ['ip', 'mac']
          organization:
            type: str
            description: Organization domain name
          os:
            type: str
            description: Dynamic address matching operating system.
          pattern_end:
            aliases: ['pattern-end']
            type: int
            description: Ending number of pattern for fqdn-group.
          pattern_start:
            aliases: ['pattern-start']
            type: int
            description: Starting number of pattern for fqdn-group.
          policy_group:
            aliases: ['policy-group']
            type: str
            description: Policy group name.
          route_tag:
            aliases: ['route-tag']
            type: int
            description: Route-tag address.
          sdn:
            type: list
            elements: str
            description: SDN.
          sdn_addr_type:
            aliases: ['sdn-addr-type']
            type: str
            description: Type of addresses to collect.
            choices: ['private', 'public', 'all']
          sdn_tag:
            aliases: ['sdn-tag']
            type: str
            description: SDN Tag.
          start_ip:
            aliases: ['start-ip']
            type: str
            description:
              - Support meta variable
              - First IP address
          start_mac:
            aliases: ['start-mac']
            type: str
            description: Support meta variable
          sub_type:
            aliases: ['sub-type']
            type: str
            description: Sub-type of address.
            choices: ['sdn', 'clearpass-spt', 'fsso', 'ems-tag', 'swc-tag', 'fortivoice-tag',
                      'fortinac-tag', 'fortipolicy-tag', 'device-identification',
                      'external-resource', 'rsso', 'obsolete', 'telemetry', '8021x']
          subnet:
            type: list
            elements: str
            description:
              - Support meta variable
              - IP address and subnet mask of address.
          subnet_name:
            aliases: ['subnet-name']
            type: str
            description: Subnet name.
          sw_version:
            aliases: ['sw-version']
            type: str
            description: Dynamic address matching software version.
          tag_detection_level:
            aliases: ['tag-detection-level']
            type: str
            description: Tag detection level of dynamic address object.
          tag_type:
            aliases: ['tag-type']
            type: str
            description: Tag type of dynamic address object.
          tags:
            type: list
            elements: str
            description: Names of object-tags applied to address.
          tenant:
            type: str
            description: Tenant.
          type:
            type: str
            description: Type of address.
            choices: ['ipmask', 'iprange', 'fqdn', 'wildcard', 'geography', 'dynamic',
                      'interface-subnet', 'fqdn-group', 'route-tag', 'mac', 'wildcard-fqdn', 'ipam']
          url:
            type: str
            description: Url.
          uuid:
            type: str
            description: Universally Unique Identifier
          visibility:
            type: str
            description: Enable/disable address visibility in the GUI.
            choices: ['disable', 'enable']
          wildcard:
            type: list
            elements: str
            description:
              - Support meta variable
              - IP address and wildcard netmask.
          wildcard_fqdn:
            aliases: ['wildcard-fqdn']
            type: str
            description:
              - Support meta variable
              - Fully Qualified Domain Name with wildcard characters.
          agent_id:
            aliases: ['agent-id']
            type: list
            elements: str
            description: Telemetry agent id.
          sso_attribute_value:
            aliases: ['sso-attribute-value']
            type: list
            elements: str
            description: RADIUS attributes value.
          tag_uuid:
            aliases: ['tag-uuid']
            type: str
            description: Foreign UUID of dynamic address object.
          passive_fqdn_learning:
            aliases: ['passive-fqdn-learning']
            type: str
            description: Enable/disable passive learning of FQDNs.
            choices: ['disable', 'enable']
          obsolete:
            type: int
            description: Obsolete.
          custom_tags:
            aliases: ['custom-tags']
            type: list
            elements: str
            description: Custom tags.
          display_with:
            aliases: ['display-with']
            type: str
            description: Display object with first tag, all tags, or just the icon & color.
            choices: ['all-tags', 'first-tag-only', 'icon-and-color']
          fabric_force_sync:
            aliases: ['fabric-force-sync']
            type: str
            description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
            choices: ['disable', 'enable']
          fabric_object_source:
            aliases: ['fabric-object-source']
            type: str
            description: Source of truth for fabric object.
            choices: ['member', 'local', 'root']
          hw_version:
            aliases: ['hw-version']
            type: str
            description: Dynamic address matching hardware version.
          ipam_allocate_unique:
            aliases: ['ipam-allocate-unique']
            type: str
            description: Allocate unique subnet for FortiIPAM managed fabric-object address.
            choices: ['disable', 'enable']
          managed_subnetwork_size:
            aliases: ['managed-subnetwork-size']
            type: str
            description: Number of IP addresses to be allocated by FortiIPAM for this address.
            choices: ['4', '8', '16', '32', '64', '128', '256', '512', '1024', '2048', '4096',
                      '8192', '16384', '32768', '65536', '131072', '262144', '524288', '1048576',
                      '2097152', '4194304', '8388608', '16777216']
      end_ip:
        aliases: ['end-ip']
        type: str
        description:
          - Support meta variable
          - Final IP address
      epg_name:
        aliases: ['epg-name']
        type: str
        description: Endpoint group name.
      fabric_object:
        aliases: ['fabric-object']
        type: str
        description: Security Fabric global object setting.
        choices: ['disable', 'enable']
      filter:
        type: str
        description: Match criteria filter.
      fqdn:
        type: str
        description:
          - Support meta variable
          - Fully Qualified Domain Name address.
      fsso_group:
        aliases: ['fsso-group']
        type: list
        elements: str
        description: FSSO group
      interface:
        type: list
        elements: str
        description: Name of interface whose IP address is to be used.
      list:
        type: list
        elements: dict
        description: List.
        suboptions:
          ip:
            type: str
            description: IP.
          net_id:
            aliases: ['net-id']
            type: str
            description: Network ID.
          obj_id:
            aliases: ['obj-id']
            type: str
            description: Object ID.
      name:
        type: str
        description: Address name.
        required: true
      node_ip_only:
        aliases: ['node-ip-only']
        type: str
        description: Enable/disable collection of node addresses only in Kubernetes.
        choices: ['disable', 'enable']
      obj_id:
        aliases: ['obj-id']
        type: str
        description: Object ID for NSX.
      obj_tag:
        aliases: ['obj-tag']
        type: str
        description: Tag of dynamic address object.
      obj_type:
        aliases: ['obj-type']
        type: str
        description: Object type.
        choices: ['ip', 'mac']
      organization:
        type: str
        description: Organization domain name
      pattern_end:
        aliases: ['pattern-end']
        type: int
        description: Ending number of pattern for fqdn-group.
      pattern_start:
        aliases: ['pattern-start']
        type: int
        description: Starting number of pattern for fqdn-group.
      policy_group:
        aliases: ['policy-group']
        type: str
        description: Policy group name.
      sdn:
        type: list
        elements: str
        description: SDN.
      sdn_addr_type:
        aliases: ['sdn-addr-type']
        type: str
        description: Type of addresses to collect.
        choices: ['private', 'public', 'all']
      sdn_tag:
        aliases: ['sdn-tag']
        type: str
        description: SDN Tag.
      start_ip:
        aliases: ['start-ip']
        type: str
        description:
          - Support meta variable
          - First IP address
      sub_type:
        aliases: ['sub-type']
        type: str
        description: Sub-type of address.
        choices: ['sdn', 'clearpass-spt', 'fsso', 'ems-tag', 'swc-tag', 'fortivoice-tag',
                  'fortinac-tag', 'fortipolicy-tag', 'device-identification', 'external-resource',
                  'rsso', 'obsolete', 'telemetry', '8021x']
      subnet:
        type: list
        elements: str
        description:
          - Support meta variable
          - IP address and subnet mask of address.
      subnet_name:
        aliases: ['subnet-name']
        type: str
        description: Subnet name.
      tag_detection_level:
        aliases: ['tag-detection-level']
        type: str
        description: Tag detection level of dynamic address object.
      tag_type:
        aliases: ['tag-type']
        type: str
        description: Tag type of dynamic address object.
      tagging:
        type: list
        elements: dict
        description: Tagging.
        suboptions:
          category:
            type: list
            elements: str
            description: Tag category.
          name:
            type: str
            description: Tagging entry name.
          tags:
            type: list
            elements: str
            description: Tags.
      tenant:
        type: str
        description: Tenant.
      type:
        type: str
        description: Type of address.
        choices: ['ipmask', 'iprange', 'fqdn', 'wildcard', 'geography', 'dynamic',
                  'interface-subnet', 'fqdn-group', 'route-tag', 'mac', 'wildcard-fqdn', 'ipam']
      uuid:
        type: str
        description: Universally Unique Identifier
      wildcard:
        type: list
        elements: str
        description:
          - Support meta variable
          - IP address and wildcard netmask.
      wildcard_fqdn:
        aliases: ['wildcard-fqdn']
        type: str
        description:
          - Support meta variable
          - Fully Qualified Domain Name with wildcard characters.
      hw_model:
        aliases: ['hw-model']
        type: str
        description: Dynamic address matching hardware model.
      route_tag:
        aliases: ['route-tag']
        type: int
        description: Route-tag address.
      sw_version:
        aliases: ['sw-version']
        type: str
        description: Dynamic address matching software version.
      macaddr:
        type: list
        elements: str
        description:
          - Support meta variable
          - Multiple MAC address ranges.
      hw_vendor:
        aliases: ['hw-vendor']
        type: str
        description: Dynamic address matching hardware vendor.
      os:
        type: str
        description: Dynamic address matching operating system.
      global_object:
        aliases: ['global-object']
        type: int
        description: Global object.
      start_mac:
        aliases: ['start-mac']
        type: str
        description:
          - Support meta variable
          - First MAC address in the range.
      end_mac:
        aliases: ['end-mac']
        type: str
        description:
          - Support meta variable
          - Last MAC address in the range.
      visibility:
        type: str
        description: Enable/disable address visibility in the GUI.
        choices: ['disable', 'enable']
      tags:
        type: list
        elements: str
        description: Names of object-tags applied to address.
      tag_uuid:
        aliases: ['tag-uuid']
        type: str
        description: Foreign UUID of dynamic address object.
      sso_attribute_value:
        aliases: ['sso-attribute-value']
        type: list
        elements: str
        description: RADIUS attributes value.
      agent_id:
        aliases: ['agent-id']
        type: list
        elements: str
        description: Telemetry agent id.
      passive_fqdn_learning:
        aliases: ['passive-fqdn-learning']
        type: str
        description: Enable/disable passive learning of FQDNs.
        choices: ['disable', 'enable']
      obsolete:
        type: int
        description: Obsolete.
      custom_tags:
        aliases: ['custom-tags']
        type: list
        elements: str
        description: Custom tags.
      display_with:
        aliases: ['display-with']
        type: str
        description: Display object with first tag, all tags, or just the icon & color.
        choices: ['all-tags', 'first-tag-only', 'icon-and-color']
      fabric_force_sync:
        aliases: ['fabric-force-sync']
        type: str
        description: Enable/disable forced synchronization of configuration objects from the root FortiGate unit to the downstream devices.
        choices: ['disable', 'enable']
      fabric_object_source:
        aliases: ['fabric-object-source']
        type: str
        description: Source of truth for fabric object.
        choices: ['member', 'local', 'root']
      hw_version:
        aliases: ['hw-version']
        type: str
        description: Dynamic address matching hardware version.
      ipam_allocate_unique:
        aliases: ['ipam-allocate-unique']
        type: str
        description: Allocate unique subnet for FortiIPAM managed fabric-object address.
        choices: ['disable', 'enable']
      managed_subnetwork_size:
        aliases: ['managed-subnetwork-size']
        type: str
        description: Number of IP addresses to be allocated by FortiIPAM for this address.
        choices: ['4', '8', '16', '32', '64', '128', '256', '512', '1024', '2048', '4096', '8192',
                  '16384', '32768', '65536', '131072', '262144', '524288', '1048576', '2097152',
                  '4194304', '8388608', '16777216']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure IPv4 addresses.
      fortinet.fmgdevice.fmgd_firewall_address:
        # workspace_locking_adom: <global or your adom name>
        device: <your own value>
        vdom: <your own value>
        state: present # <value in [present, absent]>
        firewall_address:
          name: "your value" # Required variable, string
          # _image_base64: <string>
          # allow_routing: <value in [disable, enable]>
          # associated_interface: <list or string>
          # cache_ttl: <integer>
          # clearpass_spt: <value in [unknown, healthy, quarantine, ...]>
          # color: <integer>
          # comment: <string>
          # country: <list or string>
          # dirty: <value in [dirty, clean]>
          # dynamic_mapping:
          #   - _image_base64: <string>
          #     _scope:
          #       - name: <string>
          #         vdom: <string>
          #     allow_routing: <value in [disable, enable]>
          #     associated_interface: <string>
          #     cache_ttl: <integer>
          #     clearpass_spt: <value in [unknown, healthy, quarantine, ...]>
          #     color: <integer>
          #     comment: <string>
          #     country: <list or string>
          #     dirty: <value in [dirty, clean]>
          #     end_ip: <string>
          #     end_mac: <string>
          #     epg_name: <string>
          #     fabric_object: <value in [disable, enable]>
          #     filter: <string>
          #     fqdn: <string>
          #     fsso_group: <list or string>
          #     global_object: <integer>
          #     hw_model: <string>
          #     hw_vendor: <string>
          #     interface: <string>
          #     macaddr: <list or string>
          #     node_ip_only: <value in [disable, enable]>
          #     obj_id: <string>
          #     obj_tag: <string>
          #     obj_type: <value in [ip, mac]>
          #     organization: <string>
          #     os: <string>
          #     pattern_end: <integer>
          #     pattern_start: <integer>
          #     policy_group: <string>
          #     route_tag: <integer>
          #     sdn: <list or string>
          #     sdn_addr_type: <value in [private, public, all]>
          #     sdn_tag: <string>
          #     start_ip: <string>
          #     start_mac: <string>
          #     sub_type: <value in [sdn, clearpass-spt, fsso, ...]>
          #     subnet: <list or string>
          #     subnet_name: <string>
          #     sw_version: <string>
          #     tag_detection_level: <string>
          #     tag_type: <string>
          #     tags: <list or string>
          #     tenant: <string>
          #     type: <value in [ipmask, iprange, fqdn, ...]>
          #     url: <string>
          #     uuid: <string>
          #     visibility: <value in [disable, enable]>
          #     wildcard: <list or string>
          #     wildcard_fqdn: <string>
          #     agent_id: <list or string>
          #     sso_attribute_value: <list or string>
          #     tag_uuid: <string>
          #     passive_fqdn_learning: <value in [disable, enable]>
          #     obsolete: <integer>
          #     custom_tags: <list or string>
          #     display_with: <value in [all-tags, first-tag-only, icon-and-color]>
          #     fabric_force_sync: <value in [disable, enable]>
          #     fabric_object_source: <value in [member, local, root]>
          #     hw_version: <string>
          #     ipam_allocate_unique: <value in [disable, enable]>
          #     managed_subnetwork_size: <value in [4, 8, 16, ...]>
          # end_ip: <string>
          # epg_name: <string>
          # fabric_object: <value in [disable, enable]>
          # filter: <string>
          # fqdn: <string>
          # fsso_group: <list or string>
          # interface: <list or string>
          # list:
          #   - ip: <string>
          #     net_id: <string>
          #     obj_id: <string>
          # node_ip_only: <value in [disable, enable]>
          # obj_id: <string>
          # obj_tag: <string>
          # obj_type: <value in [ip, mac]>
          # organization: <string>
          # pattern_end: <integer>
          # pattern_start: <integer>
          # policy_group: <string>
          # sdn: <list or string>
          # sdn_addr_type: <value in [private, public, all]>
          # sdn_tag: <string>
          # start_ip: <string>
          # sub_type: <value in [sdn, clearpass-spt, fsso, ...]>
          # subnet: <list or string>
          # subnet_name: <string>
          # tag_detection_level: <string>
          # tag_type: <string>
          # tagging:
          #   - category: <list or string>
          #     name: <string>
          #     tags: <list or string>
          # tenant: <string>
          # type: <value in [ipmask, iprange, fqdn, ...]>
          # uuid: <string>
          # wildcard: <list or string>
          # wildcard_fqdn: <string>
          # hw_model: <string>
          # route_tag: <integer>
          # sw_version: <string>
          # macaddr: <list or string>
          # hw_vendor: <string>
          # os: <string>
          # global_object: <integer>
          # start_mac: <string>
          # end_mac: <string>
          # visibility: <value in [disable, enable]>
          # tags: <list or string>
          # tag_uuid: <string>
          # sso_attribute_value: <list or string>
          # agent_id: <list or string>
          # passive_fqdn_learning: <value in [disable, enable]>
          # obsolete: <integer>
          # custom_tags: <list or string>
          # display_with: <value in [all-tags, first-tag-only, icon-and-color]>
          # fabric_force_sync: <value in [disable, enable]>
          # fabric_object_source: <value in [member, local, root]>
          # hw_version: <string>
          # ipam_allocate_unique: <value in [disable, enable]>
          # managed_subnetwork_size: <value in [4, 8, 16, ...]>
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
        '/pm/config/device/{device}/vdom/{vdom}/firewall/address'
    ]
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'vdom': {'required': True, 'type': 'str'},
        'firewall_address': {
            'type': 'dict', 'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
            'options': {
                '_image-base64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'allow-routing': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'associated-interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'cache-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'clearpass-spt': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': ['unknown', 'healthy', 'quarantine', 'checkup', 'infected', 'transient', 'transition'],
                    'type': 'str'
                },
                'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'country': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'dirty': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['dirty', 'clean'], 'type': 'str'},
                'dynamic_mapping': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        '_image-base64': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        '_scope': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                                'vdom': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'allow-routing': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'associated-interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'cache-ttl': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'clearpass-spt': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': ['unknown', 'healthy', 'quarantine', 'checkup', 'infected', 'transient', 'transition'],
                            'type': 'str'
                        },
                        'color': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'comment': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'country': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'dirty': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['dirty', 'clean'], 'type': 'str'},
                        'end-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'end-mac': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'epg-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'fabric-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'fqdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'fsso-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'global-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'hw-model': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'hw-vendor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'macaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'node-ip-only': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'obj-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'obj-tag': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'obj-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ip', 'mac'], 'type': 'str'},
                        'organization': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'os': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'pattern-end': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'pattern-start': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'policy-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'route-tag': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                        'sdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'sdn-addr-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['private', 'public', 'all'], 'type': 'str'},
                        'sdn-tag': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'start-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'start-mac': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'sub-type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'sdn', 'clearpass-spt', 'fsso', 'ems-tag', 'swc-tag', 'fortivoice-tag', 'fortinac-tag', 'fortipolicy-tag',
                                'device-identification', 'external-resource', 'rsso', 'obsolete', 'telemetry', '8021x'
                            ],
                            'type': 'str'
                        },
                        'subnet': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'subnet-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'sw-version': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'tag-detection-level': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'tag-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'tags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'tenant': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'type': {
                            'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                            'choices': [
                                'ipmask', 'iprange', 'fqdn', 'wildcard', 'geography', 'dynamic', 'interface-subnet', 'fqdn-group', 'route-tag', 'mac',
                                'wildcard-fqdn', 'ipam'
                            ],
                            'type': 'str'
                        },
                        'url': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'visibility': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'wildcard': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'wildcard-fqdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'agent-id': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'sso-attribute-value': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'tag-uuid': {'v_range': [['7.6.4', '']], 'type': 'str'},
                        'passive-fqdn-learning': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'obsolete': {'v_range': [['7.6.7', '']], 'type': 'int'},
                        'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                        'display-with': {'v_range': [['8.0.0', '']], 'choices': ['all-tags', 'first-tag-only', 'icon-and-color'], 'type': 'str'},
                        'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                        'hw-version': {'v_range': [['8.0.0', '']], 'type': 'str'},
                        'ipam-allocate-unique': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'managed-subnetwork-size': {
                            'v_range': [['8.0.0', '']],
                            'choices': [
                                '4', '8', '16', '32', '64', '128', '256', '512', '1024', '2048', '4096', '8192', '16384', '32768', '65536', '131072',
                                '262144', '524288', '1048576', '2097152', '4194304', '8388608', '16777216'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'end-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'epg-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'fabric-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'filter': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'fqdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'fsso-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'interface': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'list': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'net-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'obj-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'node-ip-only': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'obj-id': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'obj-tag': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'obj-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['ip', 'mac'], 'type': 'str'},
                'organization': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'pattern-end': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'pattern-start': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'policy-group': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'sdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'sdn-addr-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'choices': ['private', 'public', 'all'], 'type': 'str'},
                'sdn-tag': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'start-ip': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'sub-type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': [
                        'sdn', 'clearpass-spt', 'fsso', 'ems-tag', 'swc-tag', 'fortivoice-tag', 'fortinac-tag', 'fortipolicy-tag',
                        'device-identification', 'external-resource', 'rsso', 'obsolete', 'telemetry', '8021x'
                    ],
                    'type': 'str'
                },
                'subnet': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'subnet-name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'tag-detection-level': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'tag-type': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'tagging': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'category': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'name': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                        'tags': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'}
                    },
                    'elements': 'dict'
                },
                'tenant': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'type': {
                    'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']],
                    'choices': [
                        'ipmask', 'iprange', 'fqdn', 'wildcard', 'geography', 'dynamic', 'interface-subnet', 'fqdn-group', 'route-tag', 'mac',
                        'wildcard-fqdn', 'ipam'
                    ],
                    'type': 'str'
                },
                'uuid': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'wildcard': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'wildcard-fqdn': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'hw-model': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'route-tag': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'int'},
                'sw-version': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'macaddr': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'hw-vendor': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'os': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '']], 'type': 'str'},
                'global-object': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'int'},
                'start-mac': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'str'},
                'end-mac': {'v_range': [['7.4.8', '7.4.11'], ['7.6.4', '7.6.7']], 'type': 'str'},
                'visibility': {'v_range': [['7.4.8', '7.4.11']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'v_range': [['7.4.8', '7.4.11']], 'type': 'list', 'elements': 'str'},
                'tag-uuid': {'v_range': [['7.6.4', '']], 'type': 'str'},
                'sso-attribute-value': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'agent-id': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'passive-fqdn-learning': {'v_range': [['7.6.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'obsolete': {'v_range': [['7.6.7', '']], 'type': 'int'},
                'custom-tags': {'v_range': [['8.0.0', '']], 'type': 'list', 'elements': 'str'},
                'display-with': {'v_range': [['8.0.0', '']], 'choices': ['all-tags', 'first-tag-only', 'icon-and-color'], 'type': 'str'},
                'fabric-force-sync': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fabric-object-source': {'v_range': [['8.0.0', '']], 'choices': ['member', 'local', 'root'], 'type': 'str'},
                'hw-version': {'v_range': [['8.0.0', '']], 'type': 'str'},
                'ipam-allocate-unique': {'v_range': [['8.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'managed-subnetwork-size': {
                    'v_range': [['8.0.0', '']],
                    'choices': [
                        '4', '8', '16', '32', '64', '128', '256', '512', '1024', '2048', '4096', '8192', '16384', '32768', '65536', '131072', '262144',
                        '524288', '1048576', '2097152', '4194304', '8388608', '16777216'
                    ],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_address'),
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
