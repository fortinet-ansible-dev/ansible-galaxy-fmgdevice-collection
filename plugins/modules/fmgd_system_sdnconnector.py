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
module: fmgd_system_sdnconnector
short_description: Configure connection to SDN Connector.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.
version_added: "1.1.0"
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
    system_sdnconnector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _local_cert:
                type: str
                description: Local cert.
            access_key:
                aliases: ['access-key']
                type: str
                description: AWS / ACS access key ID.
            alt_resource_ip:
                aliases: ['alt-resource-ip']
                type: str
                description: Enable/disable AWS alternative resource IP.
                choices:
                    - 'disable'
                    - 'enable'
            api_key:
                aliases: ['api-key']
                type: list
                elements: str
                description: IBM cloud API key or service ID API key.
            azure_region:
                aliases: ['azure-region']
                type: str
                description: Azure server region.
                choices:
                    - 'global'
                    - 'china'
                    - 'germany'
                    - 'usgov'
                    - 'local'
            client_id:
                aliases: ['client-id']
                type: str
                description: Azure client ID
            client_secret:
                aliases: ['client-secret']
                type: list
                elements: str
                description: Azure client secret
            compartment_id:
                aliases: ['compartment-id']
                type: str
                description: Compartment ID.
            compute_generation:
                aliases: ['compute-generation']
                type: int
                description: Compute generation for IBM cloud infrastructure.
            domain:
                type: str
                description: Domain name.
            external_account_list:
                aliases: ['external-account-list']
                type: list
                elements: dict
                description: External account list.
                suboptions:
                    external_id:
                        aliases: ['external-id']
                        type: str
                        description: AWS external ID.
                    region_list:
                        aliases: ['region-list']
                        type: list
                        elements: str
                        description: AWS region name list.
                    role_arn:
                        aliases: ['role-arn']
                        type: str
                        description: AWS role ARN to assume.
            external_ip:
                aliases: ['external-ip']
                type: list
                elements: dict
                description: External ip.
                suboptions:
                    name:
                        type: str
                        description: External IP name.
            forwarding_rule:
                aliases: ['forwarding-rule']
                type: list
                elements: dict
                description: Forwarding rule.
                suboptions:
                    rule_name:
                        aliases: ['rule-name']
                        type: str
                        description: Forwarding rule name.
                    target:
                        type: str
                        description: Target instance name.
            gcp_project_list:
                aliases: ['gcp-project-list']
                type: list
                elements: dict
                description: Gcp project list.
                suboptions:
                    gcp_zone_list:
                        aliases: ['gcp-zone-list']
                        type: list
                        elements: str
                        description: Configure GCP zone list.
                    id:
                        type: str
                        description: GCP project ID.
            group_name:
                aliases: ['group-name']
                type: str
                description: Full path group name of computers.
            ha_status:
                aliases: ['ha-status']
                type: str
                description: Enable/disable use for FortiGate HA service.
                choices:
                    - 'disable'
                    - 'enable'
            ibm_region:
                aliases: ['ibm-region']
                type: str
                description: IBM cloud region name.
                choices:
                    - 'dallas'
                    - 'washington-dc'
                    - 'london'
                    - 'frankfurt'
                    - 'sydney'
                    - 'tokyo'
                    - 'osaka'
                    - 'toronto'
                    - 'sao-paulo'
                    - 'toronto-private'
                    - 'washington-dc-private'
                    - 'london-private'
                    - 'sao-paulo-private'
                    - 'dallas-private'
                    - 'frankfurt-private'
                    - 'sydney-private'
                    - 'tokyo-private'
                    - 'osaka-private'
                    - 'japan'
                    - 'germany'
                    - 'us-south'
                    - 'great-britain'
                    - 'australia'
                    - 'us-east'
                    - 'madrid-private'
                    - 'madrid'
            key_passwd:
                aliases: ['key-passwd']
                type: list
                elements: str
                description: Private key password.
            login_endpoint:
                aliases: ['login-endpoint']
                type: str
                description: Azure Stack login endpoint.
            name:
                type: str
                description: SDN connector name.
                required: true
            nic:
                type: list
                elements: dict
                description: Nic.
                suboptions:
                    ip:
                        type: list
                        elements: dict
                        description: Ip.
                        suboptions:
                            name:
                                type: str
                                description: IP configuration name.
                            public_ip:
                                aliases: ['public-ip']
                                type: str
                                description: Public IP name.
                            resource_group:
                                aliases: ['resource-group']
                                type: str
                                description: Resource group of Azure public IP.
                            private_ip:
                                aliases: ['private-ip']
                                type: str
                                description: Private IP address.
                    name:
                        type: str
                        description: Network interface name.
                    peer_nic:
                        aliases: ['peer-nic']
                        type: str
                        description: Peer network interface name.
            oci_cert:
                aliases: ['oci-cert']
                type: list
                elements: str
                description: OCI certificate.
            oci_fingerprint:
                aliases: ['oci-fingerprint']
                type: str
                description: Oci fingerprint.
            oci_region:
                aliases: ['oci-region']
                type: str
                description: OCI server region.
            oci_region_type:
                aliases: ['oci-region-type']
                type: str
                description: OCI region type.
                choices:
                    - 'commercial'
                    - 'government'
            password:
                type: list
                elements: str
                description: Password of the remote SDN connector as login credentials.
            private_key:
                aliases: ['private-key']
                type: str
                description: Private key of GCP service account.
            region:
                type: str
                description: AWS / ACS region name.
            resource_group:
                aliases: ['resource-group']
                type: str
                description: Azure resource group.
            resource_url:
                aliases: ['resource-url']
                type: str
                description: Azure Stack resource URL.
            route:
                type: list
                elements: dict
                description: Route.
                suboptions:
                    name:
                        type: str
                        description: Route name.
            route_table:
                aliases: ['route-table']
                type: list
                elements: dict
                description: Route table.
                suboptions:
                    name:
                        type: str
                        description: Route table name.
                    resource_group:
                        aliases: ['resource-group']
                        type: str
                        description: Resource group of Azure route table.
                    route:
                        type: list
                        elements: dict
                        description: Route.
                        suboptions:
                            name:
                                type: str
                                description: Route name.
                            next_hop:
                                aliases: ['next-hop']
                                type: str
                                description: Next hop address.
                    subscription_id:
                        aliases: ['subscription-id']
                        type: str
                        description: Subscription ID of Azure route table.
            secret_key:
                aliases: ['secret-key']
                type: list
                elements: str
                description: AWS / ACS secret access key.
            secret_token:
                aliases: ['secret-token']
                type: str
                description: Secret token of Kubernetes service account.
            server:
                type: str
                description: Server address of the remote SDN connector.
            server_ca_cert:
                aliases: ['server-ca-cert']
                type: list
                elements: str
                description: Trust only those servers whose certificate is directly/indirectly signed by this certificate.
            server_cert:
                aliases: ['server-cert']
                type: list
                elements: str
                description: Trust servers that contain this certificate only.
            server_list:
                aliases: ['server-list']
                type: list
                elements: str
                description: Server address list of the remote SDN connector.
            server_port:
                aliases: ['server-port']
                type: int
                description: Port number of the remote SDN connector.
            service_account:
                aliases: ['service-account']
                type: str
                description: GCP service account email.
            status:
                type: str
                description: Enable/disable connection to the remote SDN connector.
                choices:
                    - 'disable'
                    - 'enable'
            subscription_id:
                aliases: ['subscription-id']
                type: str
                description: Azure subscription ID.
            tenant_id:
                aliases: ['tenant-id']
                type: str
                description: Tenant ID
            type:
                type: str
                description: Type of SDN connector.
                choices:
                    - 'aci'
                    - 'aws'
                    - 'nsx'
                    - 'nuage'
                    - 'azure'
                    - 'gcp'
                    - 'oci'
                    - 'openstack'
                    - 'kubernetes'
                    - 'vmware'
                    - 'alicloud'
                    - 'sepm'
                    - 'aci-direct'
                    - 'ibm'
                    - 'nutanix'
                    - 'sap'
            update_interval:
                aliases: ['update-interval']
                type: int
                description: Dynamic object update interval
            use_metadata_iam:
                aliases: ['use-metadata-iam']
                type: str
                description: Enable/disable use of IAM role from metadata to call API.
                choices:
                    - 'disable'
                    - 'enable'
            user_id:
                aliases: ['user-id']
                type: str
                description: User ID.
            username:
                type: str
                description: Username of the remote SDN connector as login credentials.
            vcenter_password:
                aliases: ['vcenter-password']
                type: list
                elements: str
                description: VCenter server password for NSX quarantine.
            vcenter_server:
                aliases: ['vcenter-server']
                type: str
                description: VCenter server address for NSX quarantine.
            vcenter_username:
                aliases: ['vcenter-username']
                type: str
                description: VCenter server username for NSX quarantine.
            verify_certificate:
                aliases: ['verify-certificate']
                type: str
                description: Enable/disable server certificate verification.
                choices:
                    - 'disable'
                    - 'enable'
            vpc_id:
                aliases: ['vpc-id']
                type: str
                description: AWS VPC ID.
            proxy:
                type: list
                elements: str
                description: SDN proxy.
            compartment_list:
                aliases: ['compartment-list']
                type: list
                elements: dict
                description: Compartment list.
                suboptions:
                    compartment_id:
                        aliases: ['compartment-id']
                        type: str
                        description: OCI compartment ID.
            oci_region_list:
                aliases: ['oci-region-list']
                type: list
                elements: dict
                description: Oci region list.
                suboptions:
                    region:
                        type: str
                        description: OCI region.
            rest_ssl:
                aliases: ['rest-ssl']
                type: str
                description: Rest ssl.
                choices:
                    - 'disable'
                    - 'enable'
            vmx_image_url:
                aliases: ['vmx-image-url']
                type: str
                description: URL of web-hosted VMX image.
            rest_interface:
                aliases: ['rest-interface']
                type: str
                description: Interface name for REST service to listen on.
                choices:
                    - 'mgmt'
                    - 'sync'
            rest_sport:
                aliases: ['rest-sport']
                type: int
                description: REST service access port
            nsx_cert_fingerprint:
                aliases: ['nsx-cert-fingerprint']
                type: str
                description: NSX certificate fingerprint.
            vmx_service_name:
                aliases: ['vmx-service-name']
                type: str
                description: VMX Service name.
            rest_password:
                aliases: ['rest-password']
                type: list
                elements: str
                description: Password for REST service.
            gcp_project:
                aliases: ['gcp-project']
                type: str
                description: GCP project name.
            ibm_region_gen2:
                aliases: ['ibm-region-gen2']
                type: str
                description: Ibm region gen2.
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'great-britain'
            ibm_region_gen1:
                aliases: ['ibm-region-gen1']
                type: str
                description: Ibm region gen1.
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
            server_ip:
                aliases: ['server-ip']
                type: str
                description: Server address of the remote SDN connector.
            microsoft_365:
                aliases: ['microsoft-365']
                type: str
                description: Enable to use as Microsoft 365 connector.
                choices:
                    - 'disable'
                    - 'enable'
            vdom:
                type: list
                elements: str
                description: Virtual domain name of the remote SDN connector.
            message_server_port:
                aliases: ['message-server-port']
                type: int
                description: HTTP port number of the SAP message server.
            par_id:
                aliases: ['par-id']
                type: str
                description: Public address range ID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure connection to SDN Connector.
      fortinet.fmgdevice.fmgd_system_sdnconnector:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        device: <your own value>
        state: present # <value in [present, absent]>
        system_sdnconnector:
          name: "your value" # Required variable, string
          # _local_cert: <string>
          # access_key: <string>
          # alt_resource_ip: <value in [disable, enable]>
          # api_key: <list or string>
          # azure_region: <value in [global, china, germany, ...]>
          # client_id: <string>
          # client_secret: <list or string>
          # compartment_id: <string>
          # compute_generation: <integer>
          # domain: <string>
          # external_account_list:
          #   - external_id: <string>
          #     region_list: <list or string>
          #     role_arn: <string>
          # external_ip:
          #   - name: <string>
          # forwarding_rule:
          #   - rule_name: <string>
          #     target: <string>
          # gcp_project_list:
          #   - gcp_zone_list: <list or string>
          #     id: <string>
          # group_name: <string>
          # ha_status: <value in [disable, enable]>
          # ibm_region: <value in [dallas, washington-dc, london, ...]>
          # key_passwd: <list or string>
          # login_endpoint: <string>
          # nic:
          #   - ip:
          #       - name: <string>
          #         public_ip: <string>
          #         resource_group: <string>
          #         private_ip: <string>
          #     name: <string>
          #     peer_nic: <string>
          # oci_cert: <list or string>
          # oci_fingerprint: <string>
          # oci_region: <string>
          # oci_region_type: <value in [commercial, government]>
          # password: <list or string>
          # private_key: <string>
          # region: <string>
          # resource_group: <string>
          # resource_url: <string>
          # route:
          #   - name: <string>
          # route_table:
          #   - name: <string>
          #     resource_group: <string>
          #     route:
          #       - name: <string>
          #         next_hop: <string>
          #     subscription_id: <string>
          # secret_key: <list or string>
          # secret_token: <string>
          # server: <string>
          # server_ca_cert: <list or string>
          # server_cert: <list or string>
          # server_list: <list or string>
          # server_port: <integer>
          # service_account: <string>
          # status: <value in [disable, enable]>
          # subscription_id: <string>
          # tenant_id: <string>
          # type: <value in [aci, aws, nsx, ...]>
          # update_interval: <integer>
          # use_metadata_iam: <value in [disable, enable]>
          # user_id: <string>
          # username: <string>
          # vcenter_password: <list or string>
          # vcenter_server: <string>
          # vcenter_username: <string>
          # verify_certificate: <value in [disable, enable]>
          # vpc_id: <string>
          # proxy: <list or string>
          # compartment_list:
          #   - compartment_id: <string>
          # oci_region_list:
          #   - region: <string>
          # rest_ssl: <value in [disable, enable]>
          # vmx_image_url: <string>
          # rest_interface: <value in [mgmt, sync]>
          # rest_sport: <integer>
          # nsx_cert_fingerprint: <string>
          # vmx_service_name: <string>
          # rest_password: <list or string>
          # gcp_project: <string>
          # ibm_region_gen2: <value in [us-south, us-east, great-britain]>
          # ibm_region_gen1: <value in [us-south, us-east, germany, ...]>
          # server_ip: <string>
          # microsoft_365: <value in [disable, enable]>
          # vdom: <list or string>
          # message_server_port: <integer>
          # par_id: <string>
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
        '/pm/config/device/{device}/global/system/sdn-connector'
    ]
    url_params = ['device']
    module_primary_key = 'name'
    module_arg_spec = {
        'device': {'required': True, 'type': 'str'},
        'system_sdnconnector': {
            'type': 'dict',
            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
            'options': {
                '_local_cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'access-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'alt-resource-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'api-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'azure-region': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['global', 'china', 'germany', 'usgov', 'local'],
                    'type': 'str'
                },
                'client-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'client-secret': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'compartment-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'compute-generation': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'domain': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'external-account-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'external-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'region-list': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'role-arn': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'external-ip': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'forwarding-rule': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'rule-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'target': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'gcp-project-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'gcp-zone-list': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                        'id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'group-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ha-status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ibm-region': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'dallas', 'washington-dc', 'london', 'frankfurt', 'sydney', 'tokyo', 'osaka', 'toronto', 'sao-paulo', 'toronto-private',
                        'washington-dc-private', 'london-private', 'sao-paulo-private', 'dallas-private', 'frankfurt-private', 'sydney-private',
                        'tokyo-private', 'osaka-private', 'japan', 'germany', 'us-south', 'great-britain', 'australia', 'us-east', 'madrid-private',
                        'madrid'
                    ],
                    'type': 'str'
                },
                'key-passwd': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'login-endpoint': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'required': True, 'type': 'str'},
                'nic': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'ip': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'public-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'resource-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'private-ip': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'peer-nic': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'oci-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'oci-fingerprint': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'oci-region': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'oci-region-type': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['commercial', 'government'], 'type': 'str'},
                'password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'private-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'region': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'resource-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'resource-url': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'route': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'route-table': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {
                        'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'resource-group': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                        'route': {
                            'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                                'next-hop': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'subscription-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'secret-key': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'secret-token': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'str'},
                'server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'server-ca-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'server-cert': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'server-list': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'server-port': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'service-account': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'status': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'subscription-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'tenant-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'type': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': [
                        'aci', 'aws', 'nsx', 'nuage', 'azure', 'gcp', 'oci', 'openstack', 'kubernetes', 'vmware', 'alicloud', 'sepm', 'aci-direct',
                        'ibm', 'nutanix', 'sap'
                    ],
                    'type': 'str'
                },
                'update-interval': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'use-metadata-iam': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'user-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'username': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'vcenter-password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'vcenter-server': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'vcenter-username': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'verify-certificate': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vpc-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'proxy': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'compartment-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {'compartment-id': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'oci-region-list': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'type': 'list',
                    'options': {'region': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'rest-ssl': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vmx-image-url': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'rest-interface': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['mgmt', 'sync'], 'type': 'str'},
                'rest-sport': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'int'},
                'nsx-cert-fingerprint': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'vmx-service-name': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'rest-password': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'no_log': True, 'type': 'list', 'elements': 'str'},
                'gcp-project': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'type': 'str'},
                'ibm-region-gen2': {'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']], 'choices': ['us-south', 'us-east', 'great-britain'], 'type': 'str'},
                'ibm-region-gen1': {
                    'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']],
                    'choices': ['us-south', 'us-east', 'germany', 'great-britain', 'japan', 'australia'],
                    'type': 'str'
                },
                'server-ip': {'v_range': [['7.4.8', '7.4.10']], 'type': 'str'},
                'microsoft-365': {'v_range': [['7.6.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vdom': {'v_range': [['7.6.4', '']], 'type': 'list', 'elements': 'str'},
                'message-server-port': {'v_range': [['7.6.4', '']], 'type': 'int'},
                'par-id': {'v_range': [['7.6.5', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnconnector'),
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
