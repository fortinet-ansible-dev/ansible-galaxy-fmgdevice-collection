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
module: fmgd_rename
short_description: Rename an object in FortiManager.
description:
    - This module is able to configure a FortiManager device by renaming an object.
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
        required: false
        type: str
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of forticloud managed API users, this option is available with FortiManager later than 6.4.0.
        required: false
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    rename:
        description: Rename An Object.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the renamed object.
                type: str
                choices:
                    - 'antivirus_exemptlist'
                    - 'antivirus_profile'
                    - 'application_categories'
                    - 'application_custom'
                    - 'application_group'
                    - 'application_list'
                    - 'application_list_defaultnetworkservices'
                    - 'application_list_entries'
                    - 'application_name'
                    - 'authentication_rule'
                    - 'authentication_scheme'
                    - 'aws_vpce'
                    - 'azure_vwaningresspublicips'
                    - 'azure_vwanslb_permanentsecurityrules_rules'
                    - 'azure_vwanslb_temporarysecurityrules_rules'
                    - 'casb_attributematch'
                    - 'casb_attributematch_attribute'
                    - 'casb_attributematch_match'
                    - 'casb_attributematch_match_rule'
                    - 'casb_profile'
                    - 'casb_profile_saasapplication'
                    - 'casb_profile_saasapplication_accessrule'
                    - 'casb_profile_saasapplication_accessrule_attributefilter'
                    - 'casb_profile_saasapplication_advancedtenantcontrol'
                    - 'casb_profile_saasapplication_advancedtenantcontrol_attribute'
                    - 'casb_profile_saasapplication_customcontrol'
                    - 'casb_profile_saasapplication_customcontrol_attributefilter'
                    - 'casb_profile_saasapplication_customcontrol_option'
                    - 'casb_saasapplication'
                    - 'casb_saasapplication_inputattributes'
                    - 'casb_saasapplication_outputattributes'
                    - 'casb_useractivity'
                    - 'casb_useractivity_match'
                    - 'casb_useractivity_match_rules'
                    - 'casb_useractivity_match_tenantextraction_filters'
                    - 'certificate_hsmlocal'
                    - 'certificate_remote'
                    - 'diameterfilter_profile'
                    - 'dlp_datatype'
                    - 'dlp_dictionary'
                    - 'dlp_dictionary_entries'
                    - 'dlp_exactdatamatch'
                    - 'dlp_filepattern'
                    - 'dlp_fpdocsource'
                    - 'dlp_label'
                    - 'dlp_label_entries'
                    - 'dlp_profile'
                    - 'dlp_profile_rule'
                    - 'dlp_sensor'
                    - 'dlp_sensor_entries'
                    - 'dnsfilter_domainfilter'
                    - 'dnsfilter_domainfilter_entries'
                    - 'dnsfilter_profile'
                    - 'dnsfilter_profile_dnstranslation'
                    - 'dnsfilter_profile_ftgddns_filters'
                    - 'emailfilter_blockallowlist'
                    - 'emailfilter_blockallowlist_entries'
                    - 'emailfilter_bword'
                    - 'emailfilter_bword_entries'
                    - 'emailfilter_dnsbl'
                    - 'emailfilter_dnsbl_entries'
                    - 'emailfilter_iptrust'
                    - 'emailfilter_iptrust_entries'
                    - 'emailfilter_mheader'
                    - 'emailfilter_mheader_entries'
                    - 'emailfilter_profile'
                    - 'endpointcontrol_fctems'
                    - 'endpointcontrol_fctemsoverride'
                    - 'extendercontroller_extender'
                    - 'extensioncontroller_dataplan'
                    - 'extensioncontroller_extender'
                    - 'extensioncontroller_extenderprofile'
                    - 'extensioncontroller_extenderprofile_cellular_smsnotification_receiver'
                    - 'extensioncontroller_extendervap'
                    - 'extensioncontroller_fortigate'
                    - 'extensioncontroller_fortigateprofile'
                    - 'filefilter_profile'
                    - 'filefilter_profile_rules'
                    - 'firewall_accessproxy'
                    - 'firewall_accessproxy6'
                    - 'firewall_accessproxy6_apigateway'
                    - 'firewall_accessproxy6_apigateway6'
                    - 'firewall_accessproxy6_apigateway6_realservers'
                    - 'firewall_accessproxy6_apigateway_realservers'
                    - 'firewall_accessproxy_apigateway'
                    - 'firewall_accessproxy_apigateway6'
                    - 'firewall_accessproxy_apigateway6_realservers'
                    - 'firewall_accessproxy_apigateway_realservers'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_accessproxysshclientcert_certextension'
                    - 'firewall_accessproxyvirtualhost'
                    - 'firewall_address'
                    - 'firewall_address6'
                    - 'firewall_address6_subnetsegment'
                    - 'firewall_address6_tagging'
                    - 'firewall_address6template'
                    - 'firewall_address6template_subnetsegment'
                    - 'firewall_address6template_subnetsegment_values'
                    - 'firewall_address_tagging'
                    - 'firewall_addrgrp'
                    - 'firewall_addrgrp6'
                    - 'firewall_addrgrp6_tagging'
                    - 'firewall_addrgrp_tagging'
                    - 'firewall_centralsnatmap'
                    - 'firewall_dnstranslation'
                    - 'firewall_dospolicy'
                    - 'firewall_dospolicy6'
                    - 'firewall_dospolicy6_anomaly'
                    - 'firewall_identitybasedroute'
                    - 'firewall_identitybasedroute_rule'
                    - 'firewall_interfacepolicy'
                    - 'firewall_interfacepolicy6'
                    - 'firewall_internetserviceaddition'
                    - 'firewall_internetserviceaddition_entry'
                    - 'firewall_internetserviceaddition_entry_portrange'
                    - 'firewall_internetservicecustom'
                    - 'firewall_internetservicecustom_entry'
                    - 'firewall_internetservicecustomgroup'
                    - 'firewall_internetservicedefinition'
                    - 'firewall_internetservicedefinition_entry'
                    - 'firewall_internetservicedefinition_entry_portrange'
                    - 'firewall_internetserviceextension'
                    - 'firewall_internetserviceextension_disableentry'
                    - 'firewall_internetserviceextension_disableentry_ip6range'
                    - 'firewall_internetserviceextension_disableentry_iprange'
                    - 'firewall_internetserviceextension_disableentry_portrange'
                    - 'firewall_internetserviceextension_entry'
                    - 'firewall_internetserviceextension_entry_portrange'
                    - 'firewall_internetservicegroup'
                    - 'firewall_internetservicename'
                    - 'firewall_ipmacbinding_table'
                    - 'firewall_ippool'
                    - 'firewall_ippool6'
                    - 'firewall_ldbmonitor'
                    - 'firewall_localinpolicy'
                    - 'firewall_localinpolicy6'
                    - 'firewall_multicastaddress'
                    - 'firewall_multicastaddress6'
                    - 'firewall_multicastaddress6_tagging'
                    - 'firewall_multicastaddress_tagging'
                    - 'firewall_multicastpolicy'
                    - 'firewall_multicastpolicy6'
                    - 'firewall_networkservicedynamic'
                    - 'firewall_ondemandsniffer'
                    - 'firewall_pfcp'
                    - 'firewall_policy'
                    - 'firewall_profilegroup'
                    - 'firewall_profileprotocoloptions'
                    - 'firewall_proxyaddress'
                    - 'firewall_proxyaddress6'
                    - 'firewall_proxyaddress6_headergroup'
                    - 'firewall_proxyaddress6_tagging'
                    - 'firewall_proxyaddress_headergroup'
                    - 'firewall_proxyaddress_tagging'
                    - 'firewall_proxyaddrgrp'
                    - 'firewall_proxyaddrgrp6'
                    - 'firewall_proxyaddrgrp6_tagging'
                    - 'firewall_proxyaddrgrp_tagging'
                    - 'firewall_proxypolicy'
                    - 'firewall_responseshapingpolicy'
                    - 'firewall_schedule_group'
                    - 'firewall_schedule_onetime'
                    - 'firewall_schedule_recurring'
                    - 'firewall_securitypolicy'
                    - 'firewall_service_category'
                    - 'firewall_service_custom'
                    - 'firewall_service_group'
                    - 'firewall_shaper_peripshaper'
                    - 'firewall_shaper_trafficshaper'
                    - 'firewall_shapingpolicy'
                    - 'firewall_shapingprofile'
                    - 'firewall_shapingprofile_shapingentries'
                    - 'firewall_sniffer'
                    - 'firewall_sniffer_anomaly'
                    - 'firewall_ssh_hostkey'
                    - 'firewall_ssh_localca'
                    - 'firewall_ssh_localkey'
                    - 'firewall_ssl_keyringlist'
                    - 'firewall_sslserver'
                    - 'firewall_sslsshprofile'
                    - 'firewall_sslsshprofile_echoutersni'
                    - 'firewall_sslsshprofile_sslexempt'
                    - 'firewall_sslsshprofile_sslserver'
                    - 'firewall_ttlpolicy'
                    - 'firewall_vip'
                    - 'firewall_vip6'
                    - 'firewall_vip6_realservers'
                    - 'firewall_vip_realservers'
                    - 'firewall_vip_sslciphersuites'
                    - 'firewall_vipgrp'
                    - 'firewall_vipgrp6'
                    - 'firewall_wildcardfqdn_custom'
                    - 'firewall_wildcardfqdn_group'
                    - 'gtp_apnshaper'
                    - 'gtp_ieallowlist'
                    - 'gtp_ieallowlist_entries'
                    - 'gtp_rattimeoutprofile'
                    - 'icap_localserver_icapservice'
                    - 'icap_profile'
                    - 'icap_profile_icapheaders'
                    - 'icap_remoteserver'
                    - 'icap_remoteservergroup'
                    - 'icap_remoteservergroup_serverlist'
                    - 'icap_server'
                    - 'icap_servergroup'
                    - 'imageanalyzer_profile'
                    - 'ips_sensor'
                    - 'ips_sensor_entries'
                    - 'ips_sensor_entries_exemptip'
                    - 'isolator_profile'
                    - 'isolator_profile_entries'
                    - 'llm_profile'
                    - 'llm_server'
                    - 'loadbalance_flowrule'
                    - 'log_azuresecuritycenter2_filter_freestyle'
                    - 'log_azuresecuritycenter2_setting_customfieldname'
                    - 'log_azuresecuritycenter_filter_freestyle'
                    - 'log_azuresecuritycenter_setting_customfieldname'
                    - 'log_customfield'
                    - 'log_disk_filter_freestyle'
                    - 'log_fortianalyzer2_filter_freestyle'
                    - 'log_fortianalyzer2_overridefilter_freestyle'
                    - 'log_fortianalyzer3_filter_freestyle'
                    - 'log_fortianalyzer3_overridefilter_freestyle'
                    - 'log_fortianalyzer_filter_freestyle'
                    - 'log_fortianalyzer_overridefilter_freestyle'
                    - 'log_fortianalyzercloud_filter_freestyle'
                    - 'log_fortianalyzercloud_overridefilter_freestyle'
                    - 'log_fortiguard_filter_freestyle'
                    - 'log_fortiguard_overridefilter_freestyle'
                    - 'log_memory_filter_freestyle'
                    - 'log_nulldevice_filter_freestyle'
                    - 'log_syslogd2_filter_freestyle'
                    - 'log_syslogd2_overridefilter_freestyle'
                    - 'log_syslogd2_overridesetting_customfieldname'
                    - 'log_syslogd2_overridesetting_logtemplates'
                    - 'log_syslogd2_setting_customfieldname'
                    - 'log_syslogd2_setting_logtemplates'
                    - 'log_syslogd3_filter_freestyle'
                    - 'log_syslogd3_overridefilter_freestyle'
                    - 'log_syslogd3_overridesetting_customfieldname'
                    - 'log_syslogd3_overridesetting_logtemplates'
                    - 'log_syslogd3_setting_customfieldname'
                    - 'log_syslogd3_setting_logtemplates'
                    - 'log_syslogd4_filter_freestyle'
                    - 'log_syslogd4_overridefilter_freestyle'
                    - 'log_syslogd4_overridesetting_customfieldname'
                    - 'log_syslogd4_overridesetting_logtemplates'
                    - 'log_syslogd4_setting_customfieldname'
                    - 'log_syslogd4_setting_logtemplates'
                    - 'log_syslogd_filter_freestyle'
                    - 'log_syslogd_overridefilter_freestyle'
                    - 'log_syslogd_overridesetting_customfieldname'
                    - 'log_syslogd_overridesetting_logtemplates'
                    - 'log_syslogd_setting_customfieldname'
                    - 'log_syslogd_setting_logtemplates'
                    - 'log_threatweight_application'
                    - 'log_threatweight_geolocation'
                    - 'log_threatweight_web'
                    - 'log_webtrends_filter_freestyle'
                    - 'nsx_profile'
                    - 'nsxt_servicechain'
                    - 'nsxt_servicechain_serviceindex'
                    - 'pfcp_messagefilter'
                    - 'report_chart'
                    - 'report_chart_column'
                    - 'report_chart_column_mapping'
                    - 'report_chart_drilldowncharts'
                    - 'report_dataset'
                    - 'report_dataset_field'
                    - 'report_dataset_parameters'
                    - 'report_layout'
                    - 'report_layout_bodyitem'
                    - 'report_layout_bodyitem_list'
                    - 'report_layout_bodyitem_parameters'
                    - 'report_layout_page_footer_footeritem'
                    - 'report_layout_page_header_headeritem'
                    - 'report_style'
                    - 'report_theme'
                    - 'router_accesslist'
                    - 'router_accesslist6'
                    - 'router_accesslist6_rule'
                    - 'router_accesslist_rule'
                    - 'router_aspathlist'
                    - 'router_aspathlist_rule'
                    - 'router_authpath'
                    - 'router_bfd6_multihoptemplate'
                    - 'router_bfd_multihoptemplate'
                    - 'router_bgp_admindistance'
                    - 'router_bgp_aggregateaddress'
                    - 'router_bgp_aggregateaddress6'
                    - 'router_bgp_neighborgroup'
                    - 'router_bgp_neighborrange'
                    - 'router_bgp_neighborrange6'
                    - 'router_bgp_network'
                    - 'router_bgp_network6'
                    - 'router_communitylist'
                    - 'router_communitylist_rule'
                    - 'router_extcommunitylist'
                    - 'router_extcommunitylist_rule'
                    - 'router_isis_isisinterface'
                    - 'router_isis_isisnet'
                    - 'router_isis_redistribute'
                    - 'router_isis_redistribute6'
                    - 'router_isis_summaryaddress'
                    - 'router_isis_summaryaddress6'
                    - 'router_keychain'
                    - 'router_keychain_key'
                    - 'router_multicast6_interface'
                    - 'router_multicast6_pimsmglobal_rpaddress'
                    - 'router_multicast_interface'
                    - 'router_multicast_pimsmglobal_rpaddress'
                    - 'router_multicast_pimsmglobalvrf'
                    - 'router_multicast_pimsmglobalvrf_rpaddress'
                    - 'router_multicastflow'
                    - 'router_multicastflow_flows'
                    - 'router_ospf6_area'
                    - 'router_ospf6_area_ipseckeys'
                    - 'router_ospf6_area_range'
                    - 'router_ospf6_area_virtuallink'
                    - 'router_ospf6_area_virtuallink_ipseckeys'
                    - 'router_ospf6_ospf6interface'
                    - 'router_ospf6_ospf6interface_ipseckeys'
                    - 'router_ospf6_ospf6interface_neighbor'
                    - 'router_ospf6_redistribute'
                    - 'router_ospf6_summaryaddress'
                    - 'router_ospf_area'
                    - 'router_ospf_area_filterlist'
                    - 'router_ospf_area_range'
                    - 'router_ospf_area_virtuallink'
                    - 'router_ospf_area_virtuallink_md5keys'
                    - 'router_ospf_distributelist'
                    - 'router_ospf_neighbor'
                    - 'router_ospf_network'
                    - 'router_ospf_ospfinterface'
                    - 'router_ospf_ospfinterface_md5keys'
                    - 'router_ospf_redistribute'
                    - 'router_ospf_summaryaddress'
                    - 'router_policy'
                    - 'router_policy6'
                    - 'router_prefixlist'
                    - 'router_prefixlist6'
                    - 'router_prefixlist6_rule'
                    - 'router_prefixlist_rule'
                    - 'router_rip_distance'
                    - 'router_rip_distributelist'
                    - 'router_rip_interface'
                    - 'router_rip_neighbor'
                    - 'router_rip_network'
                    - 'router_rip_offsetlist'
                    - 'router_rip_redistribute'
                    - 'router_ripng_aggregateaddress'
                    - 'router_ripng_distance'
                    - 'router_ripng_distributelist'
                    - 'router_ripng_interface'
                    - 'router_ripng_neighbor'
                    - 'router_ripng_network'
                    - 'router_ripng_offsetlist'
                    - 'router_routemap'
                    - 'router_routemap_rule'
                    - 'router_static'
                    - 'router_static6'
                    - 'sctpfilter_profile'
                    - 'sctpfilter_profile_ppidfilters'
                    - 'sshfilter_profile'
                    - 'sshfilter_profile_shellcommands'
                    - 'switchcontroller_acl_group'
                    - 'switchcontroller_acl_ingress'
                    - 'switchcontroller_autoconfig_custom'
                    - 'switchcontroller_autoconfig_custom_switchbinding'
                    - 'switchcontroller_autoconfig_policy'
                    - 'switchcontroller_customcommand'
                    - 'switchcontroller_dsl_policy'
                    - 'switchcontroller_dynamicportpolicy'
                    - 'switchcontroller_dynamicportpolicy_policy'
                    - 'switchcontroller_flowtracking_aggregates'
                    - 'switchcontroller_flowtracking_collectors'
                    - 'switchcontroller_fortilinksettings'
                    - 'switchcontroller_initialconfig_template'
                    - 'switchcontroller_lldpprofile'
                    - 'switchcontroller_lldpprofile_customtlvs'
                    - 'switchcontroller_lldpprofile_medlocationservice'
                    - 'switchcontroller_lldpprofile_mednetworkpolicy'
                    - 'switchcontroller_location'
                    - 'switchcontroller_macpolicy'
                    - 'switchcontroller_managedswitch'
                    - 'switchcontroller_managedswitch_customcommand'
                    - 'switchcontroller_managedswitch_dhcpsnoopingstaticclient'
                    - 'switchcontroller_managedswitch_igmpsnooping_vlans'
                    - 'switchcontroller_managedswitch_ipsourceguard'
                    - 'switchcontroller_managedswitch_ipsourceguard_bindingentry'
                    - 'switchcontroller_managedswitch_mirror'
                    - 'switchcontroller_managedswitch_ports_dhcpsnoopoption82override'
                    - 'switchcontroller_managedswitch_remotelog'
                    - 'switchcontroller_managedswitch_routeoffloadrouter'
                    - 'switchcontroller_managedswitch_routerstatic'
                    - 'switchcontroller_managedswitch_routervrf'
                    - 'switchcontroller_managedswitch_snmpcommunity'
                    - 'switchcontroller_managedswitch_snmpcommunity_hosts'
                    - 'switchcontroller_managedswitch_snmpuser'
                    - 'switchcontroller_managedswitch_staticmac'
                    - 'switchcontroller_managedswitch_stpinstance'
                    - 'switchcontroller_managedswitch_systemdhcpserver'
                    - 'switchcontroller_managedswitch_systemdhcpserver_iprange'
                    - 'switchcontroller_managedswitch_systemdhcpserver_options'
                    - 'switchcontroller_managedswitch_systeminterface'
                    - 'switchcontroller_managedswitch_vlan'
                    - 'switchcontroller_nacdevice'
                    - 'switchcontroller_nacsettings'
                    - 'switchcontroller_portpolicy'
                    - 'switchcontroller_ptp_interfacepolicy'
                    - 'switchcontroller_ptp_policy'
                    - 'switchcontroller_ptp_profile'
                    - 'switchcontroller_qos_dot1pmap'
                    - 'switchcontroller_qos_ipdscpmap'
                    - 'switchcontroller_qos_ipdscpmap_map'
                    - 'switchcontroller_qos_qospolicy'
                    - 'switchcontroller_qos_queuepolicy'
                    - 'switchcontroller_qos_queuepolicy_cosqueue'
                    - 'switchcontroller_remotelog'
                    - 'switchcontroller_securitypolicy_8021x'
                    - 'switchcontroller_securitypolicy_localaccess'
                    - 'switchcontroller_snmpcommunity'
                    - 'switchcontroller_snmpcommunity_hosts'
                    - 'switchcontroller_snmpuser'
                    - 'switchcontroller_stormcontrolpolicy'
                    - 'switchcontroller_stpinstance'
                    - 'switchcontroller_switchgroup'
                    - 'switchcontroller_switchinterfacetag'
                    - 'switchcontroller_switchprofile'
                    - 'switchcontroller_trafficpolicy'
                    - 'switchcontroller_trafficsniffer_targetip'
                    - 'switchcontroller_trafficsniffer_targetmac'
                    - 'switchcontroller_trafficsniffer_targetport'
                    - 'switchcontroller_virtualportpool'
                    - 'switchcontroller_vlanpolicy'
                    - 'system_3gmodem_custom'
                    - 'system_5gmodem_dataplan'
                    - 'system_accprofile'
                    - 'system_acme_accounts'
                    - 'system_admin'
                    - 'system_admin_trusthosts'
                    - 'system_affinityinterrupt'
                    - 'system_affinitypacketredistribution'
                    - 'system_alias'
                    - 'system_apiuser'
                    - 'system_apiuser_trusthost'
                    - 'system_arptable'
                    - 'system_automationaction'
                    - 'system_automationaction_formdata'
                    - 'system_automationaction_httpheaders'
                    - 'system_automationcondition'
                    - 'system_automationdestination'
                    - 'system_automationstitch'
                    - 'system_automationstitch_actions'
                    - 'system_automationtrigger'
                    - 'system_automationtrigger_fields'
                    - 'system_autoscript'
                    - 'system_centralmanagement_serverlist'
                    - 'system_cloudservice'
                    - 'system_clustersync_sessionsyncfilter_customservice'
                    - 'system_csf_fabricconnector'
                    - 'system_csf_fabricdevice'
                    - 'system_csf_trustedlist'
                    - 'system_customlanguage'
                    - 'system_deviceupgradeexemptions'
                    - 'system_dhcp6_server'
                    - 'system_dhcp6_server_iprange'
                    - 'system_dhcp6_server_options'
                    - 'system_dhcp6_server_prefixrange'
                    - 'system_dhcp_server'
                    - 'system_dhcp_server_excluderange'
                    - 'system_dhcp_server_iprange'
                    - 'system_dhcp_server_options'
                    - 'system_dhcp_server_reservedaddress'
                    - 'system_dnsdatabase'
                    - 'system_dnsdatabase_dnsentry'
                    - 'system_dnsserver'
                    - 'system_dscpbasedpriority'
                    - 'system_evpn'
                    - 'system_externalresource'
                    - 'system_fabricvpn_advertisedsubnets'
                    - 'system_fabricvpn_overlays'
                    - 'system_geneve'
                    - 'system_geoipcountry'
                    - 'system_geoipoverride'
                    - 'system_geoipoverride_ip6range'
                    - 'system_geoipoverride_iprange'
                    - 'system_gretunnel'
                    - 'system_ha_hamgmtinterfaces'
                    - 'system_ha_unicastpeers'
                    - 'system_ha_vcluster'
                    - 'system_healthcheckfortiguard'
                    - 'system_interface'
                    - 'system_interface_clientoptions'
                    - 'system_interface_dhcpsnoopingserverlist'
                    - 'system_interface_ipv6_clientoptions'
                    - 'system_interface_secondaryip'
                    - 'system_interface_tagging'
                    - 'system_interface_vrrp'
                    - 'system_interface_vrrp_proxyarp'
                    - 'system_interface_wifinetworks'
                    - 'system_ipam_pools'
                    - 'system_ipam_rules'
                    - 'system_ipiptunnel'
                    - 'system_ipsecaggregate'
                    - 'system_ipv6neighborcache'
                    - 'system_ipv6tunnel'
                    - 'system_iscsi'
                    - 'system_isfqueueprofile'
                    - 'system_linkmonitor'
                    - 'system_linkmonitor_serverlist'
                    - 'system_lldp_networkpolicy'
                    - 'system_ltemodem_dataplan'
                    - 'system_mobiletunnel'
                    - 'system_mobiletunnel_network'
                    - 'system_nat64_secondaryprefix'
                    - 'system_netflow_collectors'
                    - 'system_netflow_exclusionfilters'
                    - 'system_nethsm_hagroups'
                    - 'system_nethsm_partitions'
                    - 'system_nethsm_servers'
                    - 'system_nethsm_slots'
                    - 'system_np6'
                    - 'system_np6xlite'
                    - 'system_npuvlink'
                    - 'system_ntp_ntpserver'
                    - 'system_objecttag'
                    - 'system_pcpserver_pools'
                    - 'system_physicalswitch'
                    - 'system_pppoeinterface'
                    - 'system_proxyarp'
                    - 'system_ptp_serverinterface'
                    - 'system_replacemsggroup'
                    - 'system_replacemsggroup_alertmail'
                    - 'system_replacemsggroup_nacquar'
                    - 'system_replacemsgimage'
                    - 'system_saml_serviceproviders'
                    - 'system_saml_serviceproviders_assertionattributes'
                    - 'system_sdnconnector'
                    - 'system_sdnconnector_routetable'
                    - 'system_sdnproxy'
                    - 'system_sdnvpn'
                    - 'system_sdwan_duplication'
                    - 'system_sdwan_healthcheck'
                    - 'system_sdwan_healthcheck_sla'
                    - 'system_sdwan_healthcheckfortiguard_sla'
                    - 'system_sdwan_service'
                    - 'system_sdwan_service_sla'
                    - 'system_sdwan_zone'
                    - 'system_securityrating_controls'
                    - 'system_sessionhelper'
                    - 'system_sessionttl_port'
                    - 'system_sflow_collectors'
                    - 'system_sittunnel'
                    - 'system_smcntp_ntpserver'
                    - 'system_smsserver'
                    - 'system_snmp_community'
                    - 'system_snmp_community_hosts'
                    - 'system_snmp_community_hosts6'
                    - 'system_snmp_mibview'
                    - 'system_snmp_rmonstat'
                    - 'system_snmp_user'
                    - 'system_spanport'
                    - 'system_speedtestserver'
                    - 'system_speedtestserver_host'
                    - 'system_ssoadmin'
                    - 'system_ssoforticloudadmin'
                    - 'system_ssofortigatecloudadmin'
                    - 'system_standalonecluster_clusterpeer_sessionsyncfilter_customservice'
                    - 'system_standalonecluster_monitorprefix'
                    - 'system_storage'
                    - 'system_switchinterface'
                    - 'system_tosbasedpriority'
                    - 'system_vdom'
                    - 'system_vdomexception'
                    - 'system_vdomlink'
                    - 'system_vdomnetflow_collectors'
                    - 'system_vdomproperty'
                    - 'system_vdomradiusserver'
                    - 'system_vdomsflow_collectors'
                    - 'system_virtualswitch'
                    - 'system_virtualswitch_port'
                    - 'system_virtualwanlink_healthcheck'
                    - 'system_virtualwanlink_healthcheck_sla'
                    - 'system_virtualwanlink_service'
                    - 'system_virtualwanlink_service_sla'
                    - 'system_virtualwirepair'
                    - 'system_vneinterface'
                    - 'system_vpce'
                    - 'system_vxlan'
                    - 'system_wccp'
                    - 'system_wireless_apstatus'
                    - 'system_zone'
                    - 'system_zone_tagging'
                    - 'user_adgrp'
                    - 'user_certificate'
                    - 'user_domaincontroller'
                    - 'user_domaincontroller_extraserver'
                    - 'user_exchange'
                    - 'user_externalidentityprovider'
                    - 'user_fsso'
                    - 'user_fssopolling'
                    - 'user_fssopolling_adgrp'
                    - 'user_group'
                    - 'user_group_match'
                    - 'user_krbkeytab'
                    - 'user_ldap'
                    - 'user_local'
                    - 'user_nacpolicy'
                    - 'user_oidc'
                    - 'user_passwordpolicy'
                    - 'user_peer'
                    - 'user_peergrp'
                    - 'user_pop3'
                    - 'user_quarantine_targets_macs'
                    - 'user_radius'
                    - 'user_radius_accountingserver'
                    - 'user_saml'
                    - 'user_scim'
                    - 'user_securityexemptlist'
                    - 'user_securityexemptlist_rule'
                    - 'user_setting_authports'
                    - 'user_tacacs'
                    - 'videofilter_keyword'
                    - 'videofilter_keyword_word'
                    - 'videofilter_profile'
                    - 'videofilter_profile_filters'
                    - 'videofilter_profile_fortiguardcategory_filters'
                    - 'videofilter_youtubekey'
                    - 'virtualpatch_profile'
                    - 'virtualpatch_profile_exemption'
                    - 'voip_profile'
                    - 'vpn_certificate_ca'
                    - 'vpn_certificate_crl'
                    - 'vpn_certificate_hsmlocal'
                    - 'vpn_certificate_local'
                    - 'vpn_certificate_ocspserver'
                    - 'vpn_certificate_remote'
                    - 'vpn_ipsec_concentrator'
                    - 'vpn_ipsec_fec'
                    - 'vpn_ipsec_forticlient'
                    - 'vpn_ipsec_manualkey'
                    - 'vpn_ipsec_manualkeyinterface'
                    - 'vpn_ipsec_phase1'
                    - 'vpn_ipsec_phase1_ipv4excluderange'
                    - 'vpn_ipsec_phase1_ipv6excluderange'
                    - 'vpn_ipsec_phase1interface'
                    - 'vpn_ipsec_phase1interface_ipv4excluderange'
                    - 'vpn_ipsec_phase1interface_ipv6excluderange'
                    - 'vpn_ipsec_phase2'
                    - 'vpn_ipsec_phase2interface'
                    - 'vpn_kmipserver'
                    - 'vpn_kmipserver_serverlist'
                    - 'vpn_ocvpn_forticlientaccess_authgroups'
                    - 'vpn_ocvpn_overlays'
                    - 'vpn_ocvpn_overlays_subnets'
                    - 'vpn_qkd'
                    - 'vpn_ssl_client'
                    - 'vpn_ssl_settings_authenticationrule'
                    - 'vpnsslweb_hostchecksoftware'
                    - 'vpnsslweb_hostchecksoftware_checkitemlist'
                    - 'vpnsslweb_portal'
                    - 'vpnsslweb_portal_bookmarkgroup'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks'
                    - 'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata'
                    - 'vpnsslweb_portal_landingpage_formdata'
                    - 'vpnsslweb_portal_macaddrcheckrule'
                    - 'vpnsslweb_portal_splitdns'
                    - 'vpnsslweb_userbookmark'
                    - 'vpnsslweb_userbookmark_bookmarks'
                    - 'vpnsslweb_userbookmark_bookmarks_formdata'
                    - 'vpnsslweb_usergroupbookmark'
                    - 'vpnsslweb_usergroupbookmark_bookmarks'
                    - 'vpnsslweb_usergroupbookmark_bookmarks_formdata'
                    - 'waf_mainclass'
                    - 'waf_profile'
                    - 'waf_profile_constraint_exception'
                    - 'waf_profile_method_methodpolicy'
                    - 'waf_profile_signature_customsignature'
                    - 'waf_profile_urlaccess'
                    - 'waf_profile_urlaccess_accesspattern'
                    - 'waf_signature'
                    - 'waf_subclass'
                    - 'wanopt_authgroup'
                    - 'wanopt_cacheservice_dstpeer'
                    - 'wanopt_cacheservice_srcpeer'
                    - 'wanopt_contentdeliverynetworkrule'
                    - 'wanopt_contentdeliverynetworkrule_rules'
                    - 'wanopt_contentdeliverynetworkrule_rules_matchentries'
                    - 'wanopt_contentdeliverynetworkrule_rules_skipentries'
                    - 'wanopt_profile'
                    - 'webcache_prefetch'
                    - 'webcache_reversecacheserver'
                    - 'webcache_useragent'
                    - 'webfilter_content'
                    - 'webfilter_content_entries'
                    - 'webfilter_contentheader'
                    - 'webfilter_domainlist'
                    - 'webfilter_ftgdlocalcat'
                    - 'webfilter_ftgdrisklevel'
                    - 'webfilter_override'
                    - 'webfilter_profile'
                    - 'webfilter_profile_antiphish_inspectionentries'
                    - 'webfilter_profile_ftgdwf_filters'
                    - 'webfilter_profile_ftgdwf_quota'
                    - 'webfilter_profile_ftgdwf_risk'
                    - 'webfilter_searchengine'
                    - 'webfilter_urlfilter'
                    - 'webfilter_urlfilter_entries'
                    - 'webfilter_urllist'
                    - 'webproxy_debugurl'
                    - 'webproxy_explicit'
                    - 'webproxy_explicit_pacpolicy'
                    - 'webproxy_explicitproxy'
                    - 'webproxy_fastfallback'
                    - 'webproxy_forwardserver'
                    - 'webproxy_forwardservergroup'
                    - 'webproxy_forwardservergroup_serverlist'
                    - 'webproxy_implicitproxyrule'
                    - 'webproxy_implicitproxyrule_proxyservers'
                    - 'webproxy_implicitproxysetting'
                    - 'webproxy_isolatorserver'
                    - 'webproxy_pacpolicy'
                    - 'webproxy_profile'
                    - 'webproxy_profile_headers'
                    - 'webproxy_redirectprofile'
                    - 'webproxy_redirectprofile_entries'
                    - 'webproxy_urllist'
                    - 'webproxy_urllist_entries'
                    - 'webproxy_urlmatch'
                    - 'webproxy_wisp'
                    - 'wireless_accesscontrollist'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
                    - 'wireless_apcfgprofile'
                    - 'wireless_apcfgprofile_commandlist'
                    - 'wireless_apstatus'
                    - 'wireless_arrpprofile'
                    - 'wireless_bleprofile'
                    - 'wireless_bonjourprofile'
                    - 'wireless_hotspot20_anqp3gppcellular'
                    - 'wireless_hotspot20_anqp3gppcellular_mccmnclist'
                    - 'wireless_hotspot20_anqpipaddresstype'
                    - 'wireless_hotspot20_anqpnairealm'
                    - 'wireless_hotspot20_anqpnairealm_nailist'
                    - 'wireless_hotspot20_anqpnairealm_nailist_eapmethod'
                    - 'wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam'
                    - 'wireless_hotspot20_anqpnetworkauthtype'
                    - 'wireless_hotspot20_anqproamingconsortium'
                    - 'wireless_hotspot20_anqpvenuename'
                    - 'wireless_hotspot20_anqpvenueurl'
                    - 'wireless_hotspot20_h2qpadviceofcharge'
                    - 'wireless_hotspot20_h2qpadviceofcharge_aoclist'
                    - 'wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo'
                    - 'wireless_hotspot20_h2qpconncapability'
                    - 'wireless_hotspot20_h2qpoperatorname'
                    - 'wireless_hotspot20_h2qposuprovider'
                    - 'wireless_hotspot20_h2qposuprovider_friendlyname'
                    - 'wireless_hotspot20_h2qposuprovider_servicedescription'
                    - 'wireless_hotspot20_h2qposuprovidernai'
                    - 'wireless_hotspot20_h2qposuprovidernai_nailist'
                    - 'wireless_hotspot20_h2qptermsandconditions'
                    - 'wireless_hotspot20_h2qpwanmetric'
                    - 'wireless_hotspot20_hsprofile'
                    - 'wireless_hotspot20_icon'
                    - 'wireless_hotspot20_icon_iconlist'
                    - 'wireless_hotspot20_qosmap'
                    - 'wireless_hotspot20_qosmap_dscpexcept'
                    - 'wireless_hotspot20_qosmap_dscprange'
                    - 'wireless_intercontroller_intercontrollerpeer'
                    - 'wireless_lwprofile'
                    - 'wireless_mpskprofile'
                    - 'wireless_mpskprofile_mpskgroup'
                    - 'wireless_mpskprofile_mpskgroup_mpskkey'
                    - 'wireless_nacprofile'
                    - 'wireless_qosprofile'
                    - 'wireless_region'
                    - 'wireless_setting_offendingssid'
                    - 'wireless_snmp_community'
                    - 'wireless_snmp_community_hosts'
                    - 'wireless_snmp_community_hosts6'
                    - 'wireless_snmp_user'
                    - 'wireless_ssidpolicy'
                    - 'wireless_syslogprofile'
                    - 'wireless_utmprofile'
                    - 'wireless_vap'
                    - 'wireless_vap_macfilterlist'
                    - 'wireless_vap_vlanname'
                    - 'wireless_vap_vlanpool'
                    - 'wireless_vapgroup'
                    - 'wireless_wagprofile'
                    - 'wireless_widsprofile'
                    - 'wireless_wtp'
                    - 'wireless_wtp_splittunnelingacl'
                    - 'wireless_wtpgroup'
                    - 'wireless_wtpprofile'
                    - 'wireless_wtpprofile_denymaclist'
                    - 'wireless_wtpprofile_splittunnelingacl'
                    - 'ztna_reverseconnector'
                    - 'ztna_serviceconnector'
                    - 'ztna_trafficforwardproxy'
                    - 'ztna_trafficforwardproxyreverseservice_remoteservers'
                    - 'ztna_webportal'
                    - 'ztna_webportalbookmark'
                    - 'ztna_webportalbookmark_bookmarks'
                    - 'ztna_webproxy'
                    - 'ztna_webproxy_apigateway'
                    - 'ztna_webproxy_apigateway6'
                    - 'ztna_webproxy_apigateway6_realservers'
                    - 'ztna_webproxy_apigateway_realservers'
            self:
                required: true
                description: The parameter for each selector.
                type: dict
            target:
                required: true
                description: Attribute to override for target object.
                type: dict
'''

EXAMPLES = '''
- name: Rename an object
  hosts: fortimanagers
  connection: httpapi
  vars:
    device_name: "FGVMMLTMXXXXX"
    vdom_name: "root"
  tasks:
    - name: Rename an object in FortiManager Device by using fmgd_rename module.
      fortinet.fmgdevice.fmgd_rename:
        rename:
          selector: "antivirus_exemptlist"
          self:
            vdom: "{{ vdom_name }}"
            device: "{{ device_name }}"
            exempt_list: "old_name"
          target:
            name: "new_name"
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
from ansible_collections.fortinet.fmgdevice.plugins.module_utils.napi import NAPIManager


def main():
    rename_metadata = {
        'antivirus_exemptlist': {
            'params': ['device', 'vdom', 'exempt-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/exempt-list/{exempt-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'antivirus_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_categories': {
            'params': ['device', 'categories'],
            'urls': [
                '/pm/config/device/{device}/global/application/categories/{categories}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_custom': {
            'params': ['device', 'vdom', 'custom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/custom/{custom}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_group': {
            'params': ['device', 'vdom', 'group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_list': {
            'params': ['device', 'vdom', 'list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/list/{list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_list_defaultnetworkservices': {
            'params': ['device', 'vdom', 'list', 'default-network-services'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/list/{list}/default-network-services/{default-network-services}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_list_entries': {
            'params': ['device', 'vdom', 'list', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/application/list/{list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'application_name': {
            'params': ['device', 'name'],
            'urls': [
                '/pm/config/device/{device}/global/application/name/{name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'authentication_rule': {
            'params': ['device', 'vdom', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/authentication/rule/{rule}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'authentication_scheme': {
            'params': ['device', 'vdom', 'scheme'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/authentication/scheme/{scheme}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'aws_vpce': {
            'params': ['device', 'vpce'],
            'urls': [
                '/pm/config/device/{device}/global/aws/vpce/{vpce}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'azure_vwaningresspublicips': {
            'params': ['device', 'vwan-ingress-public-IPs'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-ingress-public-IPs/{vwan-ingress-public-IPs}'
            ],
            'mkey': 'name', 'v_range': [['7.4.4', '']]
        },
        'azure_vwanslb_permanentsecurityrules_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb/permanent-security-rules/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'azure_vwanslb_temporarysecurityrules_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/azure/vwan-slb/temporary-security-rules/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'casb_attributematch': {
            'params': ['device', 'vdom', 'attribute-match'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_attributematch_attribute': {
            'params': ['device', 'vdom', 'attribute-match', 'attribute'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/attribute/{attribute}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_attributematch_match': {
            'params': ['device', 'vdom', 'attribute-match', 'match'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/match/{match}'
            ],
            'mkey': 'id', 'v_range': [['7.6.3', '']]
        },
        'casb_attributematch_match_rule': {
            'params': ['device', 'vdom', 'attribute-match', 'match', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/match/{match}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.6.3', '']]
        },
        'casb_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_profile_saasapplication': {
            'params': ['device', 'vdom', 'profile', 'saas-application'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_profile_saasapplication_accessrule': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'access-rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_profile_saasapplication_accessrule_attributefilter': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'access-rule', 'attribute-filter'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/access-rule/{access-rule}/attribute-filter'
                '/{attribute-filter}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'casb_profile_saasapplication_advancedtenantcontrol': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'advanced-tenant-control'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-c'
                'ontrol}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'casb_profile_saasapplication_advancedtenantcontrol_attribute': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'advanced-tenant-control', 'attribute'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/advanced-tenant-control/{advanced-tenant-c'
                'ontrol}/attribute/{attribute}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'casb_profile_saasapplication_customcontrol': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'custom-control'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_profile_saasapplication_customcontrol_attributefilter': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'custom-control', 'attribute-filter'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/attribute-'
                'filter/{attribute-filter}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'casb_profile_saasapplication_customcontrol_option': {
            'params': ['device', 'vdom', 'profile', 'saas-application', 'custom-control', 'option'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/profile/{profile}/saas-application/{saas-application}/custom-control/{custom-control}/option/{op'
                'tion}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_saasapplication': {
            'params': ['device', 'vdom', 'saas-application'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/saas-application/{saas-application}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_saasapplication_inputattributes': {
            'params': ['device', 'vdom', 'saas-application', 'input-attributes'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/saas-application/{saas-application}/input-attributes/{input-attributes}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'casb_saasapplication_outputattributes': {
            'params': ['device', 'vdom', 'saas-application', 'output-attributes'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/saas-application/{saas-application}/output-attributes/{output-attributes}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'casb_useractivity': {
            'params': ['device', 'vdom', 'user-activity'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_useractivity_match': {
            'params': ['device', 'vdom', 'user-activity', 'match'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}/match/{match}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_useractivity_match_rules': {
            'params': ['device', 'vdom', 'user-activity', 'match', 'rules'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}/match/{match}/rules/{rules}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'casb_useractivity_match_tenantextraction_filters': {
            'params': ['device', 'vdom', 'user-activity', 'match', 'filters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/user-activity/{user-activity}/match/{match}/tenant-extraction/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'certificate_hsmlocal': {
            'params': ['device', 'hsm-local'],
            'urls': [
                '/pm/config/device/{device}/global/certificate/hsm-local/{hsm-local}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'certificate_remote': {
            'params': ['device', 'remote'],
            'urls': [
                '/pm/config/device/{device}/global/certificate/remote/{remote}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'diameterfilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/diameter-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_datatype': {
            'params': ['device', 'vdom', 'data-type'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/data-type/{data-type}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_dictionary': {
            'params': ['device', 'vdom', 'dictionary'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/dictionary/{dictionary}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_dictionary_entries': {
            'params': ['device', 'vdom', 'dictionary', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/dictionary/{dictionary}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_exactdatamatch': {
            'params': ['device', 'vdom', 'exact-data-match'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '7.4.6'], ['7.4.8', '7.6.2'], ['7.6.4', '']]
        },
        'dlp_filepattern': {
            'params': ['device', 'vdom', 'filepattern'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/filepattern/{filepattern}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_fpdocsource': {
            'params': ['device', 'vdom', 'fp-doc-source'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/fp-doc-source/{fp-doc-source}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'dlp_label': {
            'params': ['device', 'vdom', 'label'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/label/{label}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'dlp_label_entries': {
            'params': ['device', 'vdom', 'label', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/label/{label}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'dlp_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_profile_rule': {
            'params': ['device', 'vdom', 'profile', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/profile/{profile}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_sensor': {
            'params': ['device', 'vdom', 'sensor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/sensor/{sensor}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dlp_sensor_entries': {
            'params': ['device', 'vdom', 'sensor', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/sensor/{sensor}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dnsfilter_domainfilter': {
            'params': ['device', 'vdom', 'domain-filter'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/domain-filter/{domain-filter}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dnsfilter_domainfilter_entries': {
            'params': ['device', 'vdom', 'domain-filter', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/domain-filter/{domain-filter}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dnsfilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dnsfilter_profile_dnstranslation': {
            'params': ['device', 'vdom', 'profile', 'dns-translation'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/profile/{profile}/dns-translation/{dns-translation}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'dnsfilter_profile_ftgddns_filters': {
            'params': ['device', 'vdom', 'profile', 'filters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dnsfilter/profile/{profile}/ftgd-dns/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_blockallowlist': {
            'params': ['device', 'vdom', 'block-allow-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/block-allow-list/{block-allow-list}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_blockallowlist_entries': {
            'params': ['device', 'vdom', 'block-allow-list', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/block-allow-list/{block-allow-list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_bword': {
            'params': ['device', 'vdom', 'bword'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/bword/{bword}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_bword_entries': {
            'params': ['device', 'vdom', 'bword', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/bword/{bword}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_dnsbl': {
            'params': ['device', 'vdom', 'dnsbl'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/dnsbl/{dnsbl}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_dnsbl_entries': {
            'params': ['device', 'vdom', 'dnsbl', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/dnsbl/{dnsbl}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_iptrust': {
            'params': ['device', 'vdom', 'iptrust'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/iptrust/{iptrust}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_iptrust_entries': {
            'params': ['device', 'vdom', 'iptrust', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/iptrust/{iptrust}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_mheader': {
            'params': ['device', 'vdom', 'mheader'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/mheader/{mheader}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_mheader_entries': {
            'params': ['device', 'vdom', 'mheader', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/mheader/{mheader}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'emailfilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/emailfilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'endpointcontrol_fctems': {
            'params': ['device', 'fctems'],
            'urls': [
                '/pm/config/device/{device}/global/endpoint-control/fctems/{fctems}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'endpointcontrol_fctemsoverride': {
            'params': ['device', 'vdom', 'fctems-override'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/endpoint-control/fctems-override/{fctems-override}'
            ],
            'mkey': 'ems_id', 'v_range': [['7.4.3', '']]
        },
        'extendercontroller_extender': {
            'params': ['device', 'vdom', 'extender'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'extensioncontroller_dataplan': {
            'params': ['device', 'vdom', 'dataplan'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/dataplan/{dataplan}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'extensioncontroller_extender': {
            'params': ['device', 'vdom', 'extender'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender/{extender}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'extensioncontroller_extenderprofile': {
            'params': ['device', 'vdom', 'extender-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-profile/{extender-profile}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification_receiver': {
            'params': ['device', 'vdom', 'extender-profile', 'receiver'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/receiver/{receiver'
                '}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'extensioncontroller_extendervap': {
            'params': ['device', 'vdom', 'extender-vap'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-vap/{extender-vap}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '7.4.6'], ['7.4.8', '7.6.2'], ['7.6.4', '']]
        },
        'extensioncontroller_fortigate': {
            'params': ['device', 'vdom', 'fortigate'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate/{fortigate}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'extensioncontroller_fortigateprofile': {
            'params': ['device', 'vdom', 'fortigate-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate-profile/{fortigate-profile}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'filefilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/file-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'filefilter_profile_rules': {
            'params': ['device', 'vdom', 'profile', 'rules'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/file-filter/profile/{profile}/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy': {
            'params': ['device', 'vdom', 'access-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy6': {
            'params': ['device', 'vdom', 'access-proxy6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy6/{access-proxy6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy6_apigateway': {
            'params': ['device', 'vdom', 'access-proxy6', 'api-gateway'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy6_apigateway6': {
            'params': ['device', 'vdom', 'access-proxy6', 'api-gateway6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy6_apigateway6_realservers': {
            'params': ['device', 'vdom', 'access-proxy6', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy6_apigateway_realservers': {
            'params': ['device', 'vdom', 'access-proxy6', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy6/{access-proxy6}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy_apigateway': {
            'params': ['device', 'vdom', 'access-proxy', 'api-gateway'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy_apigateway6': {
            'params': ['device', 'vdom', 'access-proxy', 'api-gateway6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy_apigateway6_realservers': {
            'params': ['device', 'vdom', 'access-proxy', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxy_apigateway_realservers': {
            'params': ['device', 'vdom', 'access-proxy', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy/{access-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['device', 'vdom', 'access-proxy-ssh-client-cert'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxysshclientcert_certextension': {
            'params': ['device', 'vdom', 'access-proxy-ssh-client-cert', 'cert-extension'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_accessproxyvirtualhost': {
            'params': ['device', 'vdom', 'access-proxy-virtual-host'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-virtual-host/{access-proxy-virtual-host}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address': {
            'params': ['device', 'vdom', 'address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address/{address}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address6': {
            'params': ['device', 'vdom', 'address6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address6/{address6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address6_subnetsegment': {
            'params': ['device', 'vdom', 'address6', 'subnet-segment'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address6/{address6}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address6_tagging': {
            'params': ['device', 'vdom', 'address6', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address6/{address6}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address6template': {
            'params': ['device', 'vdom', 'address6-template'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address6-template/{address6-template}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address6template_subnetsegment': {
            'params': ['device', 'vdom', 'address6-template', 'subnet-segment'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address6template_subnetsegment_values': {
            'params': ['device', 'vdom', 'address6-template', 'subnet-segment', 'values'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address6-template/{address6-template}/subnet-segment/{subnet-segment}/values/{values}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_address_tagging': {
            'params': ['device', 'vdom', 'address', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/address/{address}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_addrgrp': {
            'params': ['device', 'vdom', 'addrgrp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/addrgrp/{addrgrp}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_addrgrp6': {
            'params': ['device', 'vdom', 'addrgrp6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/addrgrp6/{addrgrp6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_addrgrp6_tagging': {
            'params': ['device', 'vdom', 'addrgrp6', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/addrgrp6/{addrgrp6}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_addrgrp_tagging': {
            'params': ['device', 'vdom', 'addrgrp', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/addrgrp/{addrgrp}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_centralsnatmap': {
            'params': ['device', 'vdom', 'central-snat-map'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/central-snat-map/{central-snat-map}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_dnstranslation': {
            'params': ['device', 'vdom', 'dnstranslation'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/dnstranslation/{dnstranslation}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_dospolicy': {
            'params': ['device', 'vdom', 'DoS-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/DoS-policy/{DoS-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_dospolicy6': {
            'params': ['device', 'vdom', 'DoS-policy6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/DoS-policy6/{DoS-policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_dospolicy6_anomaly': {
            'params': ['device', 'vdom', 'DoS-policy6', 'anomaly'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/DoS-policy6/{DoS-policy6}/anomaly/{anomaly}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_identitybasedroute': {
            'params': ['device', 'vdom', 'identity-based-route'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/identity-based-route/{identity-based-route}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_identitybasedroute_rule': {
            'params': ['device', 'vdom', 'identity-based-route', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/identity-based-route/{identity-based-route}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_interfacepolicy': {
            'params': ['device', 'vdom', 'interface-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/interface-policy/{interface-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_interfacepolicy6': {
            'params': ['device', 'vdom', 'interface-policy6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/interface-policy6/{interface-policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetserviceaddition': {
            'params': ['device', 'internet-service-addition'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-addition/{internet-service-addition}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetserviceaddition_entry': {
            'params': ['device', 'internet-service-addition', 'entry'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetserviceaddition_entry_portrange': {
            'params': ['device', 'internet-service-addition', 'entry', 'port-range'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-addition/{internet-service-addition}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetservicecustom': {
            'params': ['device', 'vdom', 'internet-service-custom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-custom/{internet-service-custom}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetservicecustom_entry': {
            'params': ['device', 'vdom', 'internet-service-custom', 'entry'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-custom/{internet-service-custom}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetservicecustomgroup': {
            'params': ['device', 'vdom', 'internet-service-custom-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-custom-group/{internet-service-custom-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetservicedefinition': {
            'params': ['device', 'internet-service-definition'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition_entry': {
            'params': ['device', 'internet-service-definition', 'entry'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition_entry_portrange': {
            'params': ['device', 'internet-service-definition', 'entry', 'port-range'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension': {
            'params': ['device', 'vdom', 'internet-service-extension'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetserviceextension_disableentry': {
            'params': ['device', 'vdom', 'internet-service-extension', 'disable-entry'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetserviceextension_disableentry_ip6range': {
            'params': ['device', 'vdom', 'internet-service-extension', 'disable-entry', 'ip6-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-ra'
                'nge/{ip6-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetserviceextension_disableentry_iprange': {
            'params': ['device', 'vdom', 'internet-service-extension', 'disable-entry', 'ip-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-ran'
                'ge/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetserviceextension_disableentry_portrange': {
            'params': ['device', 'vdom', 'internet-service-extension', 'disable-entry', 'port-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-r'
                'ange/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetserviceextension_entry': {
            'params': ['device', 'vdom', 'internet-service-extension', 'entry'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetserviceextension_entry_portrange': {
            'params': ['device', 'vdom', 'internet-service-extension', 'entry', 'port-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range'
                '}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'firewall_internetservicegroup': {
            'params': ['device', 'vdom', 'internet-service-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-group/{internet-service-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_internetservicename': {
            'params': ['device', 'internet-service-name'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-name/{internet-service-name}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_ipmacbinding_table': {
            'params': ['device', 'vdom', 'table'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ipmacbinding/table/{table}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_ippool': {
            'params': ['device', 'vdom', 'ippool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ippool/{ippool}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_ippool6': {
            'params': ['device', 'vdom', 'ippool6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ippool6/{ippool6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_ldbmonitor': {
            'params': ['device', 'vdom', 'ldb-monitor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ldb-monitor/{ldb-monitor}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_localinpolicy': {
            'params': ['device', 'vdom', 'local-in-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/local-in-policy/{local-in-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_localinpolicy6': {
            'params': ['device', 'vdom', 'local-in-policy6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/local-in-policy6/{local-in-policy6}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastaddress': {
            'params': ['device', 'vdom', 'multicast-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-address/{multicast-address}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastaddress6': {
            'params': ['device', 'vdom', 'multicast-address6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-address6/{multicast-address6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastaddress6_tagging': {
            'params': ['device', 'vdom', 'multicast-address6', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-address6/{multicast-address6}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastaddress_tagging': {
            'params': ['device', 'vdom', 'multicast-address', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-address/{multicast-address}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastpolicy': {
            'params': ['device', 'vdom', 'multicast-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-policy/{multicast-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_multicastpolicy6': {
            'params': ['device', 'vdom', 'multicast-policy6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/multicast-policy6/{multicast-policy6}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_networkservicedynamic': {
            'params': ['device', 'vdom', 'network-service-dynamic'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/network-service-dynamic/{network-service-dynamic}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_ondemandsniffer': {
            'params': ['device', 'vdom', 'on-demand-sniffer'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/on-demand-sniffer/{on-demand-sniffer}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'firewall_pfcp': {
            'params': ['device', 'vdom', 'pfcp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/pfcp/{pfcp}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_policy': {
            'params': ['device', 'vdom', 'policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'firewall_profilegroup': {
            'params': ['device', 'vdom', 'profile-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/profile-group/{profile-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_profileprotocoloptions': {
            'params': ['device', 'vdom', 'profile-protocol-options'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/profile-protocol-options/{profile-protocol-options}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddress': {
            'params': ['device', 'vdom', 'proxy-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address/{proxy-address}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddress6': {
            'params': ['device', 'vdom', 'proxy-address6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address6/{proxy-address6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddress6_headergroup': {
            'params': ['device', 'vdom', 'proxy-address6', 'header-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address6/{proxy-address6}/header-group/{header-group}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddress6_tagging': {
            'params': ['device', 'vdom', 'proxy-address6', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address6/{proxy-address6}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddress_headergroup': {
            'params': ['device', 'vdom', 'proxy-address', 'header-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address/{proxy-address}/header-group/{header-group}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddress_tagging': {
            'params': ['device', 'vdom', 'proxy-address', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-address/{proxy-address}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddrgrp': {
            'params': ['device', 'vdom', 'proxy-addrgrp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-addrgrp/{proxy-addrgrp}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddrgrp6': {
            'params': ['device', 'vdom', 'proxy-addrgrp6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-addrgrp6/{proxy-addrgrp6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddrgrp6_tagging': {
            'params': ['device', 'vdom', 'proxy-addrgrp6', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-addrgrp6/{proxy-addrgrp6}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxyaddrgrp_tagging': {
            'params': ['device', 'vdom', 'proxy-addrgrp', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-addrgrp/{proxy-addrgrp}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_proxypolicy': {
            'params': ['device', 'vdom', 'proxy-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/proxy-policy/{proxy-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_responseshapingpolicy': {
            'params': ['device', 'vdom', 'response-shaping-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/response-shaping-policy/{response-shaping-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_schedule_group': {
            'params': ['device', 'vdom', 'group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/schedule/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_schedule_onetime': {
            'params': ['device', 'vdom', 'onetime'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/schedule/onetime/{onetime}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_schedule_recurring': {
            'params': ['device', 'vdom', 'recurring'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/schedule/recurring/{recurring}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_securitypolicy': {
            'params': ['device', 'vdom', 'security-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/security-policy/{security-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_service_category': {
            'params': ['device', 'vdom', 'category'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/service/category/{category}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_service_custom': {
            'params': ['device', 'vdom', 'custom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/service/custom/{custom}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_service_group': {
            'params': ['device', 'vdom', 'group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/service/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shaper_peripshaper': {
            'params': ['device', 'vdom', 'per-ip-shaper'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaper/per-ip-shaper/{per-ip-shaper}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shaper_trafficshaper': {
            'params': ['device', 'vdom', 'traffic-shaper'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaper/traffic-shaper/{traffic-shaper}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shapingpolicy': {
            'params': ['device', 'vdom', 'shaping-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-policy/{shaping-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shapingprofile': {
            'params': ['device', 'vdom', 'shaping-profile'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/shaping-profile/{shaping-profile}',
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-profile/{shaping-profile}'
            ],
            'mkey': 'profile_name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_shapingprofile_shapingentries': {
            'params': ['device', 'vdom', 'shaping-profile', 'shaping-entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/shaping-profile/{shaping-profile}/shaping-entries/{shaping-entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_sniffer': {
            'params': ['device', 'vdom', 'sniffer'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_sniffer_anomaly': {
            'params': ['device', 'vdom', 'sniffer', 'anomaly'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}/anomaly/{anomaly}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_ssh_hostkey': {
            'params': ['device', 'vdom', 'host-key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/host-key/{host-key}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_ssh_localca': {
            'params': ['device', 'vdom', 'local-ca'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/local-ca/{local-ca}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_ssh_localkey': {
            'params': ['device', 'vdom', 'local-key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/local-key/{local-key}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_ssl_keyringlist': {
            'params': ['device', 'keyring-list'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/ssl/keyring-list/{keyring-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_sslserver': {
            'params': ['device', 'vdom', 'ssl-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-server/{ssl-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_sslsshprofile': {
            'params': ['device', 'vdom', 'ssl-ssh-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-ssh-profile/{ssl-ssh-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_sslsshprofile_echoutersni': {
            'params': ['device', 'vdom', 'ssl-ssh-profile', 'ech-outer-sni'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ech-outer-sni/{ech-outer-sni}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_sslsshprofile_sslexempt': {
            'params': ['device', 'vdom', 'ssl-ssh-profile', 'ssl-exempt'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-exempt/{ssl-exempt}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_sslsshprofile_sslserver': {
            'params': ['device', 'vdom', 'ssl-ssh-profile', 'ssl-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-ssh-profile/{ssl-ssh-profile}/ssl-server/{ssl-server}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_ttlpolicy': {
            'params': ['device', 'vdom', 'ttl-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ttl-policy/{ttl-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'firewall_vip': {
            'params': ['device', 'vdom', 'vip'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip/{vip}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vip6': {
            'params': ['device', 'vdom', 'vip6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip6/{vip6}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vip6_realservers': {
            'params': ['device', 'vdom', 'vip6', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip6/{vip6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vip_realservers': {
            'params': ['device', 'vdom', 'vip', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip/{vip}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vip_sslciphersuites': {
            'params': ['device', 'vdom', 'vip', 'ssl-cipher-suites'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vip/{vip}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vipgrp': {
            'params': ['device', 'vdom', 'vipgrp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vipgrp/{vipgrp}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_vipgrp6': {
            'params': ['device', 'vdom', 'vipgrp6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/vipgrp6/{vipgrp6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_wildcardfqdn_custom': {
            'params': ['device', 'vdom', 'custom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/wildcard-fqdn/custom/{custom}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'firewall_wildcardfqdn_group': {
            'params': ['device', 'vdom', 'group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/wildcard-fqdn/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'gtp_apnshaper': {
            'params': ['device', 'vdom', 'apn-shaper'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/apn-shaper/{apn-shaper}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'gtp_ieallowlist': {
            'params': ['device', 'vdom', 'ie-allow-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '7.4.6'], ['7.4.8', '7.6.1'], ['7.6.4', '']]
        },
        'gtp_ieallowlist_entries': {
            'params': ['device', 'vdom', 'ie-allow-list', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '7.4.6'], ['7.4.8', '7.6.1'], ['7.6.4', '']]
        },
        'gtp_rattimeoutprofile': {
            'params': ['device', 'vdom', 'rat-timeout-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/rat-timeout-profile/{rat-timeout-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.4.6'], ['7.4.8', '']]
        },
        'icap_localserver_icapservice': {
            'params': ['device', 'vdom', 'local-server', 'icap-service'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/local-server/{local-server}/icap-service/{icap-service}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'icap_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'icap_profile_icapheaders': {
            'params': ['device', 'vdom', 'profile', 'icap-headers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/profile/{profile}/icap-headers/{icap-headers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'icap_remoteserver': {
            'params': ['device', 'vdom', 'remote-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/remote-server/{remote-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'icap_remoteservergroup': {
            'params': ['device', 'vdom', 'remote-server-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/remote-server-group/{remote-server-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'icap_remoteservergroup_serverlist': {
            'params': ['device', 'vdom', 'remote-server-group', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/remote-server-group/{remote-server-group}/server-list/{server-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'icap_server': {
            'params': ['device', 'vdom', 'server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server/{server}'
            ],
            'mkey': 'name'
        },
        'icap_servergroup': {
            'params': ['device', 'vdom', 'server-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group/{server-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2'], ['7.6.4', '']]
        },
        'imageanalyzer_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/image-analyzer/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'ips_sensor': {
            'params': ['device', 'vdom', 'sensor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ips/sensor/{sensor}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'ips_sensor_entries': {
            'params': ['device', 'vdom', 'sensor', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ips/sensor/{sensor}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'ips_sensor_entries_exemptip': {
            'params': ['device', 'vdom', 'sensor', 'entries', 'exempt-ip'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ips/sensor/{sensor}/entries/{entries}/exempt-ip/{exempt-ip}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'isolator_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/isolator/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'isolator_profile_entries': {
            'params': ['device', 'vdom', 'profile', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/isolator/profile/{profile}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'llm_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/llm/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.6.5', '']]
        },
        'llm_server': {
            'params': ['device', 'vdom', 'server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/llm/server/{server}'
            ],
            'mkey': 'name', 'v_range': [['7.6.5', '']]
        },
        'loadbalance_flowrule': {
            'params': ['device', 'flow-rule'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/flow-rule/{flow-rule}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter2_setting_customfieldname': {
            'params': ['device', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_setting_customfieldname': {
            'params': ['device', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_customfield': {
            'params': ['device', 'vdom', 'custom-field'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/custom-field/{custom-field}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_disk_filter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/disk/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer2/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer2/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer3/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer3/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzer_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzer_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer-cloud/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer-cloud/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortiguard_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortiguard/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_fortiguard_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortiguard/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_memory_filter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/memory/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_nulldevice_filter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/null-device/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd2_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd2_overridesetting_customfieldname': {
            'params': ['device', 'vdom', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd2_overridesetting_logtemplates': {
            'params': ['device', 'vdom', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd2_setting_customfieldname': {
            'params': ['device', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd2_setting_logtemplates': {
            'params': ['device', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd3_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd3_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd3_overridesetting_customfieldname': {
            'params': ['device', 'vdom', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd3_overridesetting_logtemplates': {
            'params': ['device', 'vdom', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd3_setting_customfieldname': {
            'params': ['device', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd3_setting_logtemplates': {
            'params': ['device', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd4_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd4_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd4_overridesetting_customfieldname': {
            'params': ['device', 'vdom', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd4_overridesetting_logtemplates': {
            'params': ['device', 'vdom', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd4_setting_customfieldname': {
            'params': ['device', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd4_setting_logtemplates': {
            'params': ['device', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd_overridefilter_freestyle': {
            'params': ['device', 'vdom', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd_overridesetting_customfieldname': {
            'params': ['device', 'vdom', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd_overridesetting_logtemplates': {
            'params': ['device', 'vdom', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_syslogd_setting_customfieldname': {
            'params': ['device', 'custom-field-name'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'log_syslogd_setting_logtemplates': {
            'params': ['device', 'log-templates'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/setting/log-templates/{log-templates}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_threatweight_application': {
            'params': ['device', 'vdom', 'application'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/threat-weight/application/{application}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_threatweight_geolocation': {
            'params': ['device', 'vdom', 'geolocation'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/threat-weight/geolocation/{geolocation}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_threatweight_web': {
            'params': ['device', 'vdom', 'web'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/threat-weight/web/{web}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'log_webtrends_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/webtrends/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'nsx_profile': {
            'params': ['device', 'profile'],
            'urls': [
                '/pm/config/device/{device}/global/nsx/profile/{profile}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'nsxt_servicechain': {
            'params': ['device', 'service-chain'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'nsxt_servicechain_serviceindex': {
            'params': ['device', 'service-chain', 'service-index'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}/service-index/{service-index}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'pfcp_messagefilter': {
            'params': ['device', 'vdom', 'message-filter'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/pfcp/message-filter/{message-filter}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_chart': {
            'params': ['device', 'vdom', 'chart'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_chart_column': {
            'params': ['device', 'vdom', 'chart', 'column'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_chart_column_mapping': {
            'params': ['device', 'vdom', 'chart', 'column', 'mapping'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}/mapping/{mapping}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_chart_drilldowncharts': {
            'params': ['device', 'vdom', 'chart', 'drill-down-charts'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/drill-down-charts/{drill-down-charts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_dataset': {
            'params': ['device', 'vdom', 'dataset'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_dataset_field': {
            'params': ['device', 'vdom', 'dataset', 'field'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/field/{field}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_dataset_parameters': {
            'params': ['device', 'vdom', 'dataset', 'parameters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/parameters/{parameters}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout': {
            'params': ['device', 'vdom', 'layout'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_bodyitem': {
            'params': ['device', 'vdom', 'layout', 'body-item'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_bodyitem_list': {
            'params': ['device', 'vdom', 'layout', 'body-item', 'list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/list/{list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_bodyitem_parameters': {
            'params': ['device', 'vdom', 'layout', 'body-item', 'parameters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/parameters/{parameters}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_page_footer_footeritem': {
            'params': ['device', 'vdom', 'layout', 'footer-item'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer/footer-item/{footer-item}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_layout_page_header_headeritem': {
            'params': ['device', 'vdom', 'layout', 'header-item'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header/header-item/{header-item}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_style': {
            'params': ['device', 'vdom', 'style'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/style/{style}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'report_theme': {
            'params': ['device', 'vdom', 'theme'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/theme/{theme}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_accesslist': {
            'params': ['device', 'vdom', 'access-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/access-list/{access-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_accesslist6': {
            'params': ['device', 'vdom', 'access-list6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/access-list6/{access-list6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_accesslist6_rule': {
            'params': ['device', 'vdom', 'access-list6', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/access-list6/{access-list6}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_accesslist_rule': {
            'params': ['device', 'vdom', 'access-list', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/access-list/{access-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_aspathlist': {
            'params': ['device', 'vdom', 'aspath-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/aspath-list/{aspath-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_aspathlist_rule': {
            'params': ['device', 'vdom', 'aspath-list', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/aspath-list/{aspath-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_authpath': {
            'params': ['device', 'vdom', 'auth-path'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/auth-path/{auth-path}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bfd6_multihoptemplate': {
            'params': ['device', 'vdom', 'multihop-template'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/multihop-template/{multihop-template}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bfd_multihoptemplate': {
            'params': ['device', 'vdom', 'multihop-template'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/multihop-template/{multihop-template}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_admindistance': {
            'params': ['device', 'vdom', 'admin-distance'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/admin-distance/{admin-distance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_aggregateaddress': {
            'params': ['device', 'vdom', 'aggregate-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address/{aggregate-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_aggregateaddress6': {
            'params': ['device', 'vdom', 'aggregate-address6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address6/{aggregate-address6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_neighborgroup': {
            'params': ['device', 'vdom', 'neighbor-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-group/{neighbor-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_neighborrange': {
            'params': ['device', 'vdom', 'neighbor-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range/{neighbor-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_neighborrange6': {
            'params': ['device', 'vdom', 'neighbor-range6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range6/{neighbor-range6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_network': {
            'params': ['device', 'vdom', 'network'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_bgp_network6': {
            'params': ['device', 'vdom', 'network6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network6/{network6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_communitylist': {
            'params': ['device', 'vdom', 'community-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/community-list/{community-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_communitylist_rule': {
            'params': ['device', 'vdom', 'community-list', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/community-list/{community-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_extcommunitylist': {
            'params': ['device', 'vdom', 'extcommunity-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_extcommunitylist_rule': {
            'params': ['device', 'vdom', 'extcommunity-list', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_isis_isisinterface': {
            'params': ['device', 'vdom', 'isis-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-interface/{isis-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_isis_isisnet': {
            'params': ['device', 'vdom', 'isis-net'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-net/{isis-net}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_isis_redistribute': {
            'params': ['device', 'vdom', 'redistribute'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/redistribute/{redistribute}'
            ],
            'mkey': 'protocol', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_isis_redistribute6': {
            'params': ['device', 'vdom', 'redistribute6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/redistribute6/{redistribute6}'
            ],
            'mkey': 'protocol', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_isis_summaryaddress': {
            'params': ['device', 'vdom', 'summary-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address/{summary-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_isis_summaryaddress6': {
            'params': ['device', 'vdom', 'summary-address6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address6/{summary-address6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_keychain': {
            'params': ['device', 'vdom', 'key-chain'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_keychain_key': {
            'params': ['device', 'vdom', 'key-chain', 'key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}/key/{key}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_multicast6_interface': {
            'params': ['device', 'vdom', 'interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_multicast6_pimsmglobal_rpaddress': {
            'params': ['device', 'vdom', 'rp-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/pim-sm-global/rp-address/{rp-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_multicast_interface': {
            'params': ['device', 'vdom', 'interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobal_rpaddress': {
            'params': ['device', 'vdom', 'rp-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global/rp-address/{rp-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobalvrf': {
            'params': ['device', 'vdom', 'pim-sm-global-vrf'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}'
            ],
            'mkey': 'vrf', 'v_range': [['7.6.2', '']]
        },
        'router_multicast_pimsmglobalvrf_rpaddress': {
            'params': ['device', 'vdom', 'pim-sm-global-vrf', 'rp-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}/rp-address/{rp-address}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'router_multicastflow': {
            'params': ['device', 'vdom', 'multicast-flow'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_multicastflow_flows': {
            'params': ['device', 'vdom', 'multicast-flow', 'flows'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}/flows/{flows}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_area': {
            'params': ['device', 'vdom', 'area'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_area_ipseckeys': {
            'params': ['device', 'vdom', 'area', 'ipsec-keys'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/ipsec-keys/{ipsec-keys}'
            ],
            'mkey': 'spi', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_area_range': {
            'params': ['device', 'vdom', 'area', 'range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/range/{range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_area_virtuallink': {
            'params': ['device', 'vdom', 'area', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_area_virtuallink_ipseckeys': {
            'params': ['device', 'vdom', 'area', 'virtual-link', 'ipsec-keys'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}/ipsec-keys/{ipsec-keys}'
            ],
            'mkey': 'spi', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface': {
            'params': ['device', 'vdom', 'ospf6-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface_ipseckeys': {
            'params': ['device', 'vdom', 'ospf6-interface', 'ipsec-keys'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/ipsec-keys/{ipsec-keys}'
            ],
            'mkey': 'spi', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface_neighbor': {
            'params': ['device', 'vdom', 'ospf6-interface', 'neighbor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/neighbor/{neighbor}'
            ],
            'mkey': 'ip6', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_redistribute': {
            'params': ['device', 'vdom', 'redistribute'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/redistribute/{redistribute}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf6_summaryaddress': {
            'params': ['device', 'vdom', 'summary-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/summary-address/{summary-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_area': {
            'params': ['device', 'vdom', 'area'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_area_filterlist': {
            'params': ['device', 'vdom', 'area', 'filter-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/filter-list/{filter-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_area_range': {
            'params': ['device', 'vdom', 'area', 'range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/range/{range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_area_virtuallink': {
            'params': ['device', 'vdom', 'area', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_area_virtuallink_md5keys': {
            'params': ['device', 'vdom', 'area', 'virtual-link', 'md5-keys'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}/md5-keys/{md5-keys}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_distributelist': {
            'params': ['device', 'vdom', 'distribute-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/distribute-list/{distribute-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_neighbor': {
            'params': ['device', 'vdom', 'neighbor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/neighbor/{neighbor}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_network': {
            'params': ['device', 'vdom', 'network'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_ospfinterface': {
            'params': ['device', 'vdom', 'ospf-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_ospfinterface_md5keys': {
            'params': ['device', 'vdom', 'ospf-interface', 'md5-keys'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}/md5-keys/{md5-keys}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_redistribute': {
            'params': ['device', 'vdom', 'redistribute'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/redistribute/{redistribute}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ospf_summaryaddress': {
            'params': ['device', 'vdom', 'summary-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/summary-address/{summary-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_policy': {
            'params': ['device', 'vdom', 'policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy/{policy}'
            ],
            'mkey': 'seq_num', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_policy6': {
            'params': ['device', 'vdom', 'policy6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy6/{policy6}'
            ],
            'mkey': 'seq_num', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_prefixlist': {
            'params': ['device', 'vdom', 'prefix-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/prefix-list/{prefix-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_prefixlist6': {
            'params': ['device', 'vdom', 'prefix-list6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/prefix-list6/{prefix-list6}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_prefixlist6_rule': {
            'params': ['device', 'vdom', 'prefix-list6', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/prefix-list6/{prefix-list6}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_prefixlist_rule': {
            'params': ['device', 'vdom', 'prefix-list', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/prefix-list/{prefix-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_rip_distance': {
            'params': ['device', 'vdom', 'distance'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distance/{distance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_rip_distributelist': {
            'params': ['device', 'vdom', 'distribute-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distribute-list/{distribute-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_rip_interface': {
            'params': ['device', 'vdom', 'interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_rip_neighbor': {
            'params': ['device', 'vdom', 'neighbor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/neighbor/{neighbor}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_rip_network': {
            'params': ['device', 'vdom', 'network'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_rip_offsetlist': {
            'params': ['device', 'vdom', 'offset-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/offset-list/{offset-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_rip_redistribute': {
            'params': ['device', 'vdom', 'redistribute'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/redistribute/{redistribute}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_aggregateaddress': {
            'params': ['device', 'vdom', 'aggregate-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/aggregate-address/{aggregate-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_distance': {
            'params': ['device', 'vdom', 'distance'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distance/{distance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_distributelist': {
            'params': ['device', 'vdom', 'distribute-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distribute-list/{distribute-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_interface': {
            'params': ['device', 'vdom', 'interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_neighbor': {
            'params': ['device', 'vdom', 'neighbor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/neighbor/{neighbor}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_network': {
            'params': ['device', 'vdom', 'network'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_ripng_offsetlist': {
            'params': ['device', 'vdom', 'offset-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/offset-list/{offset-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_routemap': {
            'params': ['device', 'vdom', 'route-map'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/route-map/{route-map}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_routemap_rule': {
            'params': ['device', 'vdom', 'route-map', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/route-map/{route-map}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'router_static': {
            'params': ['device', 'vdom', 'static'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/static/{static}'
            ],
            'mkey': 'seq_num', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'router_static6': {
            'params': ['device', 'vdom', 'static6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/static6/{static6}'
            ],
            'mkey': 'seq_num', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'sctpfilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/sctp-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'sctpfilter_profile_ppidfilters': {
            'params': ['device', 'vdom', 'profile', 'ppid-filters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/sctp-filter/profile/{profile}/ppid-filters/{ppid-filters}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'sshfilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ssh-filter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'sshfilter_profile_shellcommands': {
            'params': ['device', 'vdom', 'profile', 'shell-commands'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ssh-filter/profile/{profile}/shell-commands/{shell-commands}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'switchcontroller_acl_group': {
            'params': ['device', 'vdom', 'group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_acl_ingress': {
            'params': ['device', 'vdom', 'ingress'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress/{ingress}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_autoconfig_custom': {
            'params': ['device', 'vdom', 'custom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_custom_switchbinding': {
            'params': ['device', 'vdom', 'custom', 'switch-binding'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}/switch-binding/{switch-binding}'
            ],
            'mkey': 'switch_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_policy': {
            'params': ['device', 'vdom', 'policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_customcommand': {
            'params': ['device', 'vdom', 'custom-command'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/custom-command/{custom-command}',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/global/custom-command/{custom-command}'
            ],
            'mkey': 'command_name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_dsl_policy': {
            'params': ['device', 'vdom', 'policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dsl/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy': {
            'params': ['device', 'vdom', 'dynamic-port-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['device', 'vdom', 'dynamic-port-policy', 'policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking_aggregates': {
            'params': ['device', 'vdom', 'aggregates'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/aggregates/{aggregates}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking_collectors': {
            'params': ['device', 'vdom', 'collectors'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/collectors/{collectors}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_fortilinksettings': {
            'params': ['device', 'vdom', 'fortilink-settings'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/fortilink-settings/{fortilink-settings}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_initialconfig_template': {
            'params': ['device', 'vdom', 'template'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/initial-config/template/{template}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile': {
            'params': ['device', 'vdom', 'lldp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': ['device', 'vdom', 'lldp-profile', 'custom-tlvs'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': ['device', 'vdom', 'lldp-profile', 'med-location-service'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': ['device', 'vdom', 'lldp-profile', 'med-network-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_location': {
            'params': ['device', 'vdom', 'location'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location/{location}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_macpolicy': {
            'params': ['device', 'vdom', 'mac-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/mac-policy/{mac-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['device', 'vdom', 'managed-switch'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}'
            ],
            'mkey': 'switch_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': ['device', 'vdom', 'managed-switch', 'custom-command'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'mkey': 'command_entry', 'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_dhcpsnoopingstaticclient': {
            'params': ['device', 'vdom', 'managed-switch', 'dhcp-snooping-static-client'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-c'
                'lient}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_igmpsnooping_vlans': {
            'params': ['device', 'vdom', 'managed-switch', 'vlans'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/igmp-snooping/vlans/{vlans}'
            ],
            'mkey': 'vlan_name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': ['device', 'vdom', 'managed-switch', 'ip-source-guard'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'mkey': 'port', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': ['device', 'vdom', 'managed-switch', 'ip-source-guard', 'binding-entry'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{bi'
                'nding-entry}'
            ],
            'mkey': 'entry_name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_mirror': {
            'params': ['device', 'vdom', 'managed-switch', 'mirror'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/mirror/{mirror}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override': {
            'params': ['device', 'vdom', 'managed-switch', 'ports', 'dhcp-snoop-option82-override'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-sn'
                'oop-option82-override}'
            ],
            'mkey': 'vlan_name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': ['device', 'vdom', 'managed-switch', 'remote-log'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_routeoffloadrouter': {
            'params': ['device', 'vdom', 'managed-switch', 'route-offload-router'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}'
            ],
            'mkey': 'vlan_name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_managedswitch_routerstatic': {
            'params': ['device', 'vdom', 'managed-switch', 'router-static'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/router-static/{router-static}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'switchcontroller_managedswitch_routervrf': {
            'params': ['device', 'vdom', 'managed-switch', 'router-vrf'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/router-vrf/{router-vrf}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': ['device', 'vdom', 'managed-switch', 'snmp-community'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': ['device', 'vdom', 'managed-switch', 'snmp-community', 'hosts'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': ['device', 'vdom', 'managed-switch', 'snmp-user'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_staticmac': {
            'params': ['device', 'vdom', 'managed-switch', 'static-mac'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/static-mac/{static-mac}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_stpinstance': {
            'params': ['device', 'vdom', 'managed-switch', 'stp-instance'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-instance/{stp-instance}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.0'], ['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_systemdhcpserver': {
            'params': ['device', 'vdom', 'managed-switch', 'system-dhcp-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/system-dhcp-server/{system-dhcp-server}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'switchcontroller_managedswitch_systemdhcpserver_iprange': {
            'params': ['device', 'vdom', 'managed-switch', 'system-dhcp-server', 'ip-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/system-dhcp-server/{system-dhcp-server}/ip-range/{i'
                'p-range}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'switchcontroller_managedswitch_systemdhcpserver_options': {
            'params': ['device', 'vdom', 'managed-switch', 'system-dhcp-server', 'options'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/system-dhcp-server/{system-dhcp-server}/options/{op'
                'tions}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'switchcontroller_managedswitch_systeminterface': {
            'params': ['device', 'vdom', 'managed-switch', 'system-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/system-interface/{system-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'switchcontroller_managedswitch_vlan': {
            'params': ['device', 'vdom', 'managed-switch', 'vlan'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}'
            ],
            'mkey': 'vlan_name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_nacdevice': {
            'params': ['device', 'vdom', 'nac-device'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-device/{nac-device}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_nacsettings': {
            'params': ['device', 'vdom', 'nac-settings'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-settings/{nac-settings}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_portpolicy': {
            'params': ['device', 'vdom', 'port-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/port-policy/{port-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_ptp_interfacepolicy': {
            'params': ['device', 'vdom', 'interface-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/interface-policy/{interface-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_ptp_policy': {
            'params': ['device', 'vdom', 'policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_ptp_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_qos_dot1pmap': {
            'params': ['device', 'vdom', 'dot1p-map'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/dot1p-map/{dot1p-map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': ['device', 'vdom', 'ip-dscp-map'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': ['device', 'vdom', 'ip-dscp-map', 'map'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_qos_qospolicy': {
            'params': ['device', 'vdom', 'qos-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/qos-policy/{qos-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_qos_queuepolicy': {
            'params': ['device', 'vdom', 'queue-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': ['device', 'vdom', 'queue-policy', 'cos-queue'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_remotelog': {
            'params': ['device', 'vdom', 'remote-log'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/remote-log/{remote-log}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': ['device', 'vdom', '802-1X'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/802-1X/{802-1X}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_securitypolicy_localaccess': {
            'params': ['device', 'vdom', 'local-access'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/local-access/{local-access}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_snmpcommunity': {
            'params': ['device', 'vdom', 'snmp-community'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_snmpcommunity_hosts': {
            'params': ['device', 'vdom', 'snmp-community', 'hosts'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_snmpuser': {
            'params': ['device', 'vdom', 'snmp-user'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-user/{snmp-user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_stormcontrolpolicy': {
            'params': ['device', 'vdom', 'storm-control-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/storm-control-policy/{storm-control-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_stpinstance': {
            'params': ['device', 'vdom', 'stp-instance'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/stp-instance/{stp-instance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_switchgroup': {
            'params': ['device', 'vdom', 'switch-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-group/{switch-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_switchinterfacetag': {
            'params': ['device', 'vdom', 'switch-interface-tag'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-interface-tag/{switch-interface-tag}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_switchprofile': {
            'params': ['device', 'vdom', 'switch-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-profile/{switch-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_trafficpolicy': {
            'params': ['device', 'vdom', 'traffic-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-policy/{traffic-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetip': {
            'params': ['device', 'vdom', 'target-ip'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-ip/{target-ip}'
            ],
            'mkey': 'ip', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetmac': {
            'params': ['device', 'vdom', 'target-mac'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-mac/{target-mac}'
            ],
            'mkey': 'mac', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetport': {
            'params': ['device', 'vdom', 'target-port'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-port/{target-port}'
            ],
            'mkey': 'switch_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_virtualportpool': {
            'params': ['device', 'vdom', 'virtual-port-pool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/virtual-port-pool/{virtual-port-pool}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'switchcontroller_vlanpolicy': {
            'params': ['device', 'vdom', 'vlan-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/vlan-policy/{vlan-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_3gmodem_custom': {
            'params': ['device', 'vdom', 'custom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/3g-modem/custom/{custom}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_5gmodem_dataplan': {
            'params': ['device', 'data-plan'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem/data-plan/{data-plan}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_accprofile': {
            'params': ['device', 'accprofile'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_acme_accounts': {
            'params': ['device', 'accounts'],
            'urls': [
                '/pm/config/device/{device}/global/system/acme/accounts/{accounts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_admin': {
            'params': ['device', 'admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/admin/{admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_admin_trusthosts': {
            'params': ['device', 'admin', 'trusthosts'],
            'urls': [
                '/pm/config/device/{device}/global/system/admin/{admin}/trusthosts/{trusthosts}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_affinityinterrupt': {
            'params': ['device', 'affinity-interrupt'],
            'urls': [
                '/pm/config/device/{device}/global/system/affinity-interrupt/{affinity-interrupt}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_affinitypacketredistribution': {
            'params': ['device', 'affinity-packet-redistribution'],
            'urls': [
                '/pm/config/device/{device}/global/system/affinity-packet-redistribution/{affinity-packet-redistribution}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_alias': {
            'params': ['device', 'alias'],
            'urls': [
                '/pm/config/device/{device}/global/system/alias/{alias}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_apiuser': {
            'params': ['device', 'api-user'],
            'urls': [
                '/pm/config/device/{device}/global/system/api-user/{api-user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_apiuser_trusthost': {
            'params': ['device', 'api-user', 'trusthost'],
            'urls': [
                '/pm/config/device/{device}/global/system/api-user/{api-user}/trusthost/{trusthost}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_arptable': {
            'params': ['device', 'vdom', 'arp-table'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/arp-table/{arp-table}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationaction': {
            'params': ['device', 'automation-action'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationaction_formdata': {
            'params': ['device', 'automation-action', 'form-data'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}/form-data/{form-data}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'system_automationaction_httpheaders': {
            'params': ['device', 'automation-action', 'http-headers'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}/http-headers/{http-headers}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationcondition': {
            'params': ['device', 'automation-condition'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-condition/{automation-condition}'
            ],
            'mkey': 'name', 'v_range': [['7.4.6', '7.4.10'], ['7.6.2', '']]
        },
        'system_automationdestination': {
            'params': ['device', 'automation-destination'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-destination/{automation-destination}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationstitch': {
            'params': ['device', 'automation-stitch'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationstitch_actions': {
            'params': ['device', 'automation-stitch', 'actions'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}/actions/{actions}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationtrigger': {
            'params': ['device', 'automation-trigger'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_automationtrigger_fields': {
            'params': ['device', 'automation-trigger', 'fields'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}/fields/{fields}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_autoscript': {
            'params': ['device', 'auto-script'],
            'urls': [
                '/pm/config/device/{device}/global/system/auto-script/{auto-script}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_centralmanagement_serverlist': {
            'params': ['device', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/central-management/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_cloudservice': {
            'params': ['device', 'cloud-service'],
            'urls': [
                '/pm/config/device/{device}/global/system/cloud-service/{cloud-service}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'system_clustersync_sessionsyncfilter_customservice': {
            'params': ['device', 'cluster-sync', 'custom-service'],
            'urls': [
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}/session-sync-filter/custom-service/{custom-service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_csf_fabricconnector': {
            'params': ['device', 'fabric-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/fabric-connector/{fabric-connector}'
            ],
            'mkey': 'serial', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_csf_fabricdevice': {
            'params': ['device', 'fabric-device'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/fabric-device/{fabric-device}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_csf_trustedlist': {
            'params': ['device', 'trusted-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/trusted-list/{trusted-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_customlanguage': {
            'params': ['device', 'custom-language'],
            'urls': [
                '/pm/config/device/{device}/global/system/custom-language/{custom-language}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_deviceupgradeexemptions': {
            'params': ['device', 'device-upgrade-exemptions'],
            'urls': [
                '/pm/config/device/{device}/global/system/device-upgrade-exemptions/{device-upgrade-exemptions}'
            ],
            'mkey': 'id', 'v_range': [['7.6.4', '']]
        },
        'system_dhcp6_server': {
            'params': ['device', 'vdom', 'server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_dhcp6_server_iprange': {
            'params': ['device', 'vdom', 'server', 'ip-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_dhcp6_server_options': {
            'params': ['device', 'vdom', 'server', 'options'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/options/{options}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_dhcp6_server_prefixrange': {
            'params': ['device', 'vdom', 'server', 'prefix-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/prefix-range/{prefix-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_dhcp_server': {
            'params': ['device', 'vdom', 'server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_dhcp_server_excluderange': {
            'params': ['device', 'vdom', 'server', 'exclude-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}/exclude-range/{exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_dhcp_server_iprange': {
            'params': ['device', 'vdom', 'server', 'ip-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_dhcp_server_options': {
            'params': ['device', 'vdom', 'server', 'options'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}/options/{options}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_dhcp_server_reservedaddress': {
            'params': ['device', 'vdom', 'server', 'reserved-address'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp/server/{server}/reserved-address/{reserved-address}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_dnsdatabase': {
            'params': ['device', 'vdom', 'dns-database'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_dnsdatabase_dnsentry': {
            'params': ['device', 'vdom', 'dns-database', 'dns-entry'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}/dns-entry/{dns-entry}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_dnsserver': {
            'params': ['device', 'vdom', 'dns-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-server/{dns-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_dscpbasedpriority': {
            'params': ['device', 'dscp-based-priority'],
            'urls': [
                '/pm/config/device/{device}/global/system/dscp-based-priority/{dscp-based-priority}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_evpn': {
            'params': ['device', 'vdom', 'evpn'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/evpn/{evpn}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_externalresource': {
            'params': ['device', 'vdom', 'external-resource'],
            'urls': [
                '/pm/config/device/{device}/global/system/external-resource/{external-resource}',
                '/pm/config/device/{device}/vdom/{vdom}/system/external-resource/{external-resource}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_fabricvpn_advertisedsubnets': {
            'params': ['device', 'advertised-subnets'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn/advertised-subnets/{advertised-subnets}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_fabricvpn_overlays': {
            'params': ['device', 'overlays'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn/overlays/{overlays}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_geneve': {
            'params': ['device', 'vdom', 'geneve'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/geneve/{geneve}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_geoipcountry': {
            'params': ['device', 'geoip-country'],
            'urls': [
                '/pm/config/device/{device}/global/system/geoip-country/{geoip-country}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_geoipoverride': {
            'params': ['device', 'geoip-override'],
            'urls': [
                '/pm/config/device/{device}/global/system/geoip-override/{geoip-override}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_geoipoverride_ip6range': {
            'params': ['device', 'geoip-override', 'ip6-range'],
            'urls': [
                '/pm/config/device/{device}/global/system/geoip-override/{geoip-override}/ip6-range/{ip6-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_geoipoverride_iprange': {
            'params': ['device', 'geoip-override', 'ip-range'],
            'urls': [
                '/pm/config/device/{device}/global/system/geoip-override/{geoip-override}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_gretunnel': {
            'params': ['device', 'vdom', 'gre-tunnel'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/gre-tunnel/{gre-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ha_hamgmtinterfaces': {
            'params': ['device', 'ha-mgmt-interfaces'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/ha-mgmt-interfaces/{ha-mgmt-interfaces}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ha_unicastpeers': {
            'params': ['device', 'unicast-peers'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/unicast-peers/{unicast-peers}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ha_vcluster': {
            'params': ['device', 'vcluster'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/vcluster/{vcluster}'
            ],
            'mkey': 'vcluster_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_healthcheckfortiguard': {
            'params': ['device', 'health-check-fortiguard'],
            'urls': [
                '/pm/config/device/{device}/global/system/health-check-fortiguard/{health-check-fortiguard}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'system_interface': {
            'params': ['device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_clientoptions': {
            'params': ['device', 'interface', 'client-options'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/client-options/{client-options}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_dhcpsnoopingserverlist': {
            'params': ['device', 'interface', 'dhcp-snooping-server-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/dhcp-snooping-server-list/{dhcp-snooping-server-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_ipv6_clientoptions': {
            'params': ['device', 'interface', 'client-options'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/client-options/{client-options}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_interface_secondaryip': {
            'params': ['device', 'interface', 'secondaryip'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/secondaryip/{secondaryip}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_tagging': {
            'params': ['device', 'interface', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_vrrp': {
            'params': ['device', 'interface', 'vrrp'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}'
            ],
            'mkey': 'vrid', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_vrrp_proxyarp': {
            'params': ['device', 'interface', 'vrrp', 'proxy-arp'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_interface_wifinetworks': {
            'params': ['device', 'interface', 'wifi-networks'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/wifi-networks/{wifi-networks}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ipam_pools': {
            'params': ['device', 'pools'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/pools/{pools}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ipam_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ipiptunnel': {
            'params': ['device', 'vdom', 'ipip-tunnel'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipip-tunnel/{ipip-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ipsecaggregate': {
            'params': ['device', 'vdom', 'ipsec-aggregate'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipsec-aggregate/{ipsec-aggregate}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ipv6neighborcache': {
            'params': ['device', 'vdom', 'ipv6-neighbor-cache'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-neighbor-cache/{ipv6-neighbor-cache}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ipv6tunnel': {
            'params': ['device', 'vdom', 'ipv6-tunnel'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-tunnel/{ipv6-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_iscsi': {
            'params': ['device', 'iscsi'],
            'urls': [
                '/pm/config/device/{device}/global/system/iscsi/{iscsi}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_isfqueueprofile': {
            'params': ['device', 'isf-queue-profile'],
            'urls': [
                '/pm/config/device/{device}/global/system/isf-queue-profile/{isf-queue-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_linkmonitor': {
            'params': ['device', 'vdom', 'link-monitor'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_linkmonitor_serverlist': {
            'params': ['device', 'vdom', 'link-monitor', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy': {
            'params': ['device', 'vdom', 'network-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ltemodem_dataplan': {
            'params': ['device', 'data-plan'],
            'urls': [
                '/pm/config/device/{device}/global/system/lte-modem/data-plan/{data-plan}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'system_mobiletunnel': {
            'params': ['device', 'vdom', 'mobile-tunnel'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_mobiletunnel_network': {
            'params': ['device', 'vdom', 'mobile-tunnel', 'network'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_nat64_secondaryprefix': {
            'params': ['device', 'vdom', 'secondary-prefix'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/nat64/secondary-prefix/{secondary-prefix}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_netflow_collectors': {
            'params': ['device', 'collectors'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_netflow_exclusionfilters': {
            'params': ['device', 'exclusion-filters'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow/exclusion-filters/{exclusion-filters}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_nethsm_hagroups': {
            'params': ['device', 'hagroups'],
            'urls': [
                '/pm/config/device/{device}/global/system/nethsm/hagroups/{hagroups}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_nethsm_partitions': {
            'params': ['device', 'partitions'],
            'urls': [
                '/pm/config/device/{device}/global/system/nethsm/partitions/{partitions}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_nethsm_servers': {
            'params': ['device', 'servers'],
            'urls': [
                '/pm/config/device/{device}/global/system/nethsm/servers/{servers}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_nethsm_slots': {
            'params': ['device', 'slots'],
            'urls': [
                '/pm/config/device/{device}/global/system/nethsm/slots/{slots}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_np6': {
            'params': ['device', 'np6'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6/{np6}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_np6xlite': {
            'params': ['device', 'np6xlite'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6xlite/{np6xlite}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_npuvlink': {
            'params': ['device', 'npu-vlink'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-vlink/{npu-vlink}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ntp_ntpserver': {
            'params': ['device', 'ntpserver'],
            'urls': [
                '/pm/config/device/{device}/global/system/ntp/ntpserver/{ntpserver}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_objecttag': {
            'params': ['device', 'vdom', 'object-tag'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/object-tag/{object-tag}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10']]
        },
        'system_pcpserver_pools': {
            'params': ['device', 'vdom', 'pools'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pcp-server/pools/{pools}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'system_physicalswitch': {
            'params': ['device', 'physical-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/physical-switch/{physical-switch}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_pppoeinterface': {
            'params': ['device', 'vdom', 'pppoe-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pppoe-interface/{pppoe-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_proxyarp': {
            'params': ['device', 'vdom', 'proxy-arp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/proxy-arp/{proxy-arp}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ptp_serverinterface': {
            'params': ['device', 'server-interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/ptp/server-interface/{server-interface}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_replacemsggroup': {
            'params': ['device', 'vdom', 'replacemsg-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/replacemsg-group/{replacemsg-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_replacemsggroup_alertmail': {
            'params': ['device', 'vdom', 'replacemsg-group', 'alertmail'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/replacemsg-group/{replacemsg-group}/alertmail/{alertmail}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_replacemsggroup_nacquar': {
            'params': ['device', 'vdom', 'replacemsg-group', 'nac-quar'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/replacemsg-group/{replacemsg-group}/nac-quar/{nac-quar}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_replacemsgimage': {
            'params': ['device', 'replacemsg-image'],
            'urls': [
                '/pm/config/device/{device}/global/system/replacemsg-image/{replacemsg-image}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_saml_serviceproviders': {
            'params': ['device', 'service-providers'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_saml_serviceproviders_assertionattributes': {
            'params': ['device', 'service-providers', 'assertion-attributes'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}/assertion-attributes/{assertion-attributes}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdnconnector': {
            'params': ['device', 'sdn-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnconnector_routetable': {
            'params': ['device', 'sdn-connector', 'route-table'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-connector/{sdn-connector}/route-table/{route-table}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnproxy': {
            'params': ['device', 'sdn-proxy'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-proxy/{sdn-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_sdnvpn': {
            'params': ['device', 'sdn-vpn'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-vpn/{sdn-vpn}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'system_sdwan_duplication': {
            'params': ['device', 'vdom', 'duplication'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/duplication/{duplication}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheck': {
            'params': ['device', 'vdom', 'health-check'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheck_sla': {
            'params': ['device', 'vdom', 'health-check', 'sla'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheckfortiguard_sla': {
            'params': ['device', 'vdom', 'health-check-fortiguard', 'sla'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard/{health-check-fortiguard}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_sdwan_service': {
            'params': ['device', 'vdom', 'service'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_service_sla': {
            'params': ['device', 'vdom', 'service', 'sla'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sdwan_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/zone/{zone}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_securityrating_controls': {
            'params': ['device', 'controls'],
            'urls': [
                '/pm/config/device/{device}/global/system/security-rating/controls/{controls}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'system_sessionhelper': {
            'params': ['device', 'session-helper'],
            'urls': [
                '/pm/config/device/{device}/global/system/session-helper/{session-helper}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sessionttl_port': {
            'params': ['device', 'vdom', 'port'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/session-ttl/port/{port}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_sflow_collectors': {
            'params': ['device', 'collectors'],
            'urls': [
                '/pm/config/device/{device}/global/system/sflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_sittunnel': {
            'params': ['device', 'vdom', 'sit-tunnel'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sit-tunnel/{sit-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_smcntp_ntpserver': {
            'params': ['device', 'ntpserver'],
            'urls': [
                '/pm/config/device/{device}/global/system/smc-ntp/ntpserver/{ntpserver}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_smsserver': {
            'params': ['device', 'sms-server'],
            'urls': [
                '/pm/config/device/{device}/global/system/sms-server/{sms-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_snmp_community': {
            'params': ['device', 'community'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_snmp_community_hosts': {
            'params': ['device', 'community', 'hosts'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_snmp_community_hosts6': {
            'params': ['device', 'community', 'hosts6'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_snmp_mibview': {
            'params': ['device', 'mib-view'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/mib-view/{mib-view}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_snmp_rmonstat': {
            'params': ['device', 'rmon-stat'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/rmon-stat/{rmon-stat}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_snmp_user': {
            'params': ['device', 'user'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/user/{user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_spanport': {
            'params': ['device', 'span-port'],
            'urls': [
                '/pm/config/device/{device}/global/system/span-port/{span-port}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_speedtestserver': {
            'params': ['device', 'vdom', 'speed-test-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_speedtestserver_host': {
            'params': ['device', 'vdom', 'speed-test-server', 'host'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}/host/{host}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ssoadmin': {
            'params': ['device', 'sso-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-admin/{sso-admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ssoforticloudadmin': {
            'params': ['device', 'sso-forticloud-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-forticloud-admin/{sso-forticloud-admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_ssofortigatecloudadmin': {
            'params': ['device', 'sso-fortigate-cloud-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-fortigate-cloud-admin/{sso-fortigate-cloud-admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_standalonecluster_clusterpeer_sessionsyncfilter_customservice': {
            'params': ['device', 'cluster-peer', 'custom-service'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}/session-sync-filter/custom-service/{custom-service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_standalonecluster_monitorprefix': {
            'params': ['device', 'monitor-prefix'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/monitor-prefix/{monitor-prefix}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'system_storage': {
            'params': ['device', 'storage'],
            'urls': [
                '/pm/config/device/{device}/global/system/storage/{storage}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_switchinterface': {
            'params': ['device', 'switch-interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/switch-interface/{switch-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_tosbasedpriority': {
            'params': ['device', 'tos-based-priority'],
            'urls': [
                '/pm/config/device/{device}/global/system/tos-based-priority/{tos-based-priority}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdom': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom/{vdom}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdomexception': {
            'params': ['device', 'vdom-exception'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-exception/{vdom-exception}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdomlink': {
            'params': ['device', 'vdom-link'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-link/{vdom-link}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdomnetflow_collectors': {
            'params': ['device', 'vdom', 'collectors'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-netflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdomproperty': {
            'params': ['device', 'vdom-property'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-property/{vdom-property}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdomradiusserver': {
            'params': ['device', 'vdom-radius-server'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-radius-server/{vdom-radius-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_vdomsflow_collectors': {
            'params': ['device', 'vdom', 'collectors'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-sflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_virtualswitch': {
            'params': ['device', 'virtual-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_virtualswitch_port': {
            'params': ['device', 'virtual-switch', 'port'],
            'urls': [
                '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}/port/{port}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_virtualwanlink_healthcheck': {
            'params': ['device', 'vdom', 'health-check'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'system_virtualwanlink_healthcheck_sla': {
            'params': ['device', 'vdom', 'health-check', 'sla'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'system_virtualwanlink_service': {
            'params': ['device', 'vdom', 'service'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'system_virtualwanlink_service_sla': {
            'params': ['device', 'vdom', 'service', 'sla'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '7.6.2']]
        },
        'system_virtualwirepair': {
            'params': ['device', 'vdom', 'virtual-wire-pair'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wire-pair/{virtual-wire-pair}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'system_vneinterface': {
            'params': ['device', 'vdom', 'vne-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vne-interface/{vne-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.6.0', '']]
        },
        'system_vpce': {
            'params': ['device', 'vpce'],
            'urls': [
                '/pm/config/device/{device}/global/system/vpce/{vpce}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_vxlan': {
            'params': ['device', 'vdom', 'vxlan'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vxlan/{vxlan}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_wccp': {
            'params': ['device', 'vdom', 'wccp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/wccp/{wccp}'
            ],
            'mkey': 'service_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_wireless_apstatus': {
            'params': ['device', 'ap-status'],
            'urls': [
                '/pm/config/device/{device}/global/system/wireless/ap-status/{ap-status}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'system_zone_tagging': {
            'params': ['device', 'vdom', 'zone', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'user_adgrp': {
            'params': ['device', 'vdom', 'adgrp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/adgrp/{adgrp}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_certificate': {
            'params': ['device', 'vdom', 'certificate'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/certificate/{certificate}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_domaincontroller': {
            'params': ['device', 'vdom', 'domain-controller'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/domain-controller/{domain-controller}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_domaincontroller_extraserver': {
            'params': ['device', 'vdom', 'domain-controller', 'extra-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/domain-controller/{domain-controller}/extra-server/{extra-server}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_exchange': {
            'params': ['device', 'vdom', 'exchange'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/exchange/{exchange}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_externalidentityprovider': {
            'params': ['device', 'vdom', 'external-identity-provider'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/external-identity-provider/{external-identity-provider}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_fsso': {
            'params': ['device', 'vdom', 'fsso'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/fsso/{fsso}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_fssopolling': {
            'params': ['device', 'vdom', 'fsso-polling'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/fsso-polling/{fsso-polling}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_fssopolling_adgrp': {
            'params': ['device', 'vdom', 'fsso-polling', 'adgrp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/fsso-polling/{fsso-polling}/adgrp/{adgrp}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_group': {
            'params': ['device', 'vdom', 'group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/group/{group}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_group_match': {
            'params': ['device', 'vdom', 'group', 'match'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/group/{group}/match/{match}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_krbkeytab': {
            'params': ['device', 'vdom', 'krb-keytab'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/krb-keytab/{krb-keytab}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_ldap': {
            'params': ['device', 'vdom', 'ldap'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/ldap/{ldap}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_local': {
            'params': ['device', 'vdom', 'local'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/local/{local}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_nacpolicy': {
            'params': ['device', 'vdom', 'nac-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy/{nac-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'user_oidc': {
            'params': ['device', 'vdom', 'oidc'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/oidc/{oidc}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'user_passwordpolicy': {
            'params': ['device', 'vdom', 'password-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/password-policy/{password-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_peer': {
            'params': ['device', 'vdom', 'peer'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/peer/{peer}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_peergrp': {
            'params': ['device', 'vdom', 'peergrp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/peergrp/{peergrp}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_pop3': {
            'params': ['device', 'vdom', 'pop3'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/pop3/{pop3}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_quarantine_targets_macs': {
            'params': ['device', 'vdom', 'targets', 'macs'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets/{targets}/macs/{macs}'
            ],
            'mkey': 'mac', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'user_radius': {
            'params': ['device', 'vdom', 'radius'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/radius/{radius}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_radius_accountingserver': {
            'params': ['device', 'vdom', 'radius', 'accounting-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/radius/{radius}/accounting-server/{accounting-server}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_saml': {
            'params': ['device', 'vdom', 'saml'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/saml/{saml}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_scim': {
            'params': ['device', 'vdom', 'scim'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/scim/{scim}'
            ],
            'mkey': 'name', 'v_range': [['7.6.0', '7.6.2'], ['7.6.4', '']]
        },
        'user_securityexemptlist': {
            'params': ['device', 'vdom', 'security-exempt-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/security-exempt-list/{security-exempt-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_securityexemptlist_rule': {
            'params': ['device', 'vdom', 'security-exempt-list', 'rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/security-exempt-list/{security-exempt-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'user_setting_authports': {
            'params': ['device', 'vdom', 'auth-ports'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/setting/auth-ports/{auth-ports}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'user_tacacs': {
            'params': ['device', 'vdom', 'tacacs+'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/tacacs+/{tacacs+}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_keyword': {
            'params': ['device', 'vdom', 'keyword'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/keyword/{keyword}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_keyword_word': {
            'params': ['device', 'vdom', 'keyword', 'word'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/keyword/{keyword}/word/{word}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_profile_filters': {
            'params': ['device', 'vdom', 'profile', 'filters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/profile/{profile}/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_profile_fortiguardcategory_filters': {
            'params': ['device', 'vdom', 'profile', 'filters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/profile/{profile}/fortiguard-category/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'videofilter_youtubekey': {
            'params': ['device', 'vdom', 'youtube-key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/youtube-key/{youtube-key}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'virtualpatch_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/virtual-patch/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'virtualpatch_profile_exemption': {
            'params': ['device', 'vdom', 'profile', 'exemption'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/virtual-patch/profile/{profile}/exemption/{exemption}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'voip_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/voip/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpn_certificate_ca': {
            'params': ['device', 'vdom', 'ca'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/ca/{ca}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpn_certificate_crl': {
            'params': ['device', 'vdom', 'crl'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/crl/{crl}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_certificate_hsmlocal': {
            'params': ['device', 'vdom', 'hsm-local'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/hsm-local/{hsm-local}'
            ],
            'mkey': 'name', 'v_range': [['7.6.3', '']]
        },
        'vpn_certificate_local': {
            'params': ['device', 'vdom', 'local'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/local/{local}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_certificate_ocspserver': {
            'params': ['device', 'vdom', 'ocsp-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/ocsp-server/{ocsp-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpn_certificate_remote': {
            'params': ['device', 'vdom', 'remote'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/remote/{remote}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpn_ipsec_concentrator': {
            'params': ['device', 'vdom', 'concentrator'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/concentrator/{concentrator}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_fec': {
            'params': ['device', 'vdom', 'fec'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/fec/{fec}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpn_ipsec_forticlient': {
            'params': ['device', 'vdom', 'forticlient'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/forticlient/{forticlient}'
            ],
            'mkey': 'realm', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_manualkey': {
            'params': ['device', 'vdom', 'manualkey'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey/{manualkey}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_manualkeyinterface': {
            'params': ['device', 'vdom', 'manualkey-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey-interface/{manualkey-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1': {
            'params': ['device', 'vdom', 'phase1'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1_ipv4excluderange': {
            'params': ['device', 'vdom', 'phase1', 'ipv4-exclude-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1_ipv6excluderange': {
            'params': ['device', 'vdom', 'phase1', 'ipv6-exclude-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv6-exclude-range/{ipv6-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface': {
            'params': ['device', 'vdom', 'phase1-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface_ipv4excluderange': {
            'params': ['device', 'vdom', 'phase1-interface', 'ipv4-exclude-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface_ipv6excluderange': {
            'params': ['device', 'vdom', 'phase1-interface', 'ipv6-exclude-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv6-exclude-range/{ipv6-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase2': {
            'params': ['device', 'vdom', 'phase2'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2/{phase2}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase2interface': {
            'params': ['device', 'vdom', 'phase2-interface'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{phase2-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_kmipserver': {
            'params': ['device', 'vdom', 'kmip-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'vpn_kmipserver_serverlist': {
            'params': ['device', 'vdom', 'kmip-server', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'vpn_ocvpn_forticlientaccess_authgroups': {
            'params': ['device', 'vdom', 'auth-groups'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/forticlient-access/auth-groups/{auth-groups}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ocvpn_overlays': {
            'params': ['device', 'vdom', 'overlays'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ocvpn_overlays_subnets': {
            'params': ['device', 'vdom', 'overlays', 'subnets'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}/subnets/{subnets}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_qkd': {
            'params': ['device', 'vdom', 'qkd'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/qkd/{qkd}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'vpn_ssl_client': {
            'params': ['device', 'vdom', 'client'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/client/{client}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['device', 'vdom', 'authentication-rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'mkey': 'id', 'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnsslweb_hostchecksoftware': {
            'params': ['device', 'vdom', 'host-check-software'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/host-check-software/{host-check-software}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_hostchecksoftware_checkitemlist': {
            'params': ['device', 'vdom', 'host-check-software', 'check-item-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/host-check-software/{host-check-software}/check-item-list/{check-item-list}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal': {
            'params': ['device', 'vdom', 'portal'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_bookmarkgroup': {
            'params': ['device', 'vdom', 'portal', 'bookmark-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks': {
            'params': ['device', 'vdom', 'portal', 'bookmark-group', 'bookmarks'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_bookmarkgroup_bookmarks_formdata': {
            'params': ['device', 'vdom', 'portal', 'bookmark-group', 'bookmarks', 'form-data'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/bookmark-group/{bookmark-group}/bookmarks/{bookmarks}/form-data/{form-dat'
                'a}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_landingpage_formdata': {
            'params': ['device', 'vdom', 'portal', 'form-data'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/landing-page/form-data/{form-data}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_macaddrcheckrule': {
            'params': ['device', 'vdom', 'portal', 'mac-addr-check-rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/mac-addr-check-rule/{mac-addr-check-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_portal_splitdns': {
            'params': ['device', 'vdom', 'portal', 'split-dns'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/portal/{portal}/split-dns/{split-dns}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'vpnsslweb_userbookmark': {
            'params': ['device', 'vdom', 'user-bookmark'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpnsslweb_userbookmark_bookmarks': {
            'params': ['device', 'vdom', 'user-bookmark', 'bookmarks'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpnsslweb_userbookmark_bookmarks_formdata': {
            'params': ['device', 'vdom', 'user-bookmark', 'bookmarks', 'form-data'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark': {
            'params': ['device', 'vdom', 'user-group-bookmark'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks': {
            'params': ['device', 'vdom', 'user-group-bookmark', 'bookmarks'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks_formdata': {
            'params': ['device', 'vdom', 'user-group-bookmark', 'bookmarks', 'form-data'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'waf_mainclass': {
            'params': ['device', 'main-class'],
            'urls': [
                '/pm/config/device/{device}/global/waf/main-class/{main-class}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_profile_constraint_exception': {
            'params': ['device', 'vdom', 'profile', 'exception'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}/constraint/exception/{exception}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_profile_method_methodpolicy': {
            'params': ['device', 'vdom', 'profile', 'method-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}/method/method-policy/{method-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_profile_signature_customsignature': {
            'params': ['device', 'vdom', 'profile', 'custom-signature'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}/signature/custom-signature/{custom-signature}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_profile_urlaccess': {
            'params': ['device', 'vdom', 'profile', 'url-access'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}/url-access/{url-access}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_profile_urlaccess_accesspattern': {
            'params': ['device', 'vdom', 'profile', 'url-access', 'access-pattern'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/waf/profile/{profile}/url-access/{url-access}/access-pattern/{access-pattern}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_signature': {
            'params': ['device', 'signature'],
            'urls': [
                '/pm/config/device/{device}/global/waf/signature/{signature}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'waf_subclass': {
            'params': ['device', 'sub-class'],
            'urls': [
                '/pm/config/device/{device}/global/waf/sub-class/{sub-class}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'wanopt_authgroup': {
            'params': ['device', 'vdom', 'auth-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wanopt/auth-group/{auth-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'wanopt_cacheservice_dstpeer': {
            'params': ['device', 'vdom', 'dst-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service/dst-peer/{dst-peer}',
                '/pm/config/device/{device}/vdom/{vdom}/wanopt/cache-service/dst-peer/{dst-peer}'
            ],
            'mkey': 'device_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wanopt_cacheservice_srcpeer': {
            'params': ['device', 'vdom', 'src-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service/src-peer/{src-peer}',
                '/pm/config/device/{device}/vdom/{vdom}/wanopt/cache-service/src-peer/{src-peer}'
            ],
            'mkey': 'device_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule': {
            'params': ['device', 'content-delivery-network-rule'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules': {
            'params': ['device', 'content-delivery-network-rule', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_matchentries': {
            'params': ['device', 'content-delivery-network-rule', 'rules', 'match-entries'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/match-entries/{match-en'
                'tries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_skipentries': {
            'params': ['device', 'content-delivery-network-rule', 'rules', 'skip-entries'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/skip-entries/{skip-entr'
                'ies}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wanopt_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wanopt/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webcache_prefetch': {
            'params': ['device', 'vdom', 'prefetch'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webcache/prefetch/{prefetch}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webcache_reversecacheserver': {
            'params': ['device', 'vdom', 'reverse-cache-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webcache/reverse-cache-server/{reverse-cache-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webcache_useragent': {
            'params': ['device', 'vdom', 'user-agent'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webcache/user-agent/{user-agent}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_content': {
            'params': ['device', 'vdom', 'content'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/content/{content}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_content_entries': {
            'params': ['device', 'vdom', 'content', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/content/{content}/entries/{entries}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_contentheader': {
            'params': ['device', 'vdom', 'content-header'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/content-header/{content-header}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_domainlist': {
            'params': ['device', 'vdom', 'domain-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/domain-list/{domain-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_ftgdlocalcat': {
            'params': ['device', 'vdom', 'ftgd-local-cat'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-local-cat/{ftgd-local-cat}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_ftgdrisklevel': {
            'params': ['device', 'vdom', 'ftgd-risk-level'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-risk-level/{ftgd-risk-level}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.2', '']]
        },
        'webfilter_override': {
            'params': ['device', 'vdom', 'override'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/override/{override}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webfilter_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_profile_antiphish_inspectionentries': {
            'params': ['device', 'vdom', 'profile', 'inspection-entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/antiphish/inspection-entries/{inspection-entries}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_profile_ftgdwf_filters': {
            'params': ['device', 'vdom', 'profile', 'filters'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/ftgd-wf/filters/{filters}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_profile_ftgdwf_quota': {
            'params': ['device', 'vdom', 'profile', 'quota'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/ftgd-wf/quota/{quota}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_profile_ftgdwf_risk': {
            'params': ['device', 'vdom', 'profile', 'risk'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/profile/{profile}/ftgd-wf/risk/{risk}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_searchengine': {
            'params': ['device', 'vdom', 'search-engine'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/search-engine/{search-engine}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webfilter_urlfilter': {
            'params': ['device', 'vdom', 'urlfilter'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/urlfilter/{urlfilter}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_urlfilter_entries': {
            'params': ['device', 'vdom', 'urlfilter', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/urlfilter/{urlfilter}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webfilter_urllist': {
            'params': ['device', 'vdom', 'url-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/url-list/{url-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_debugurl': {
            'params': ['device', 'vdom', 'debug-url'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/debug-url/{debug-url}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webproxy_explicit': {
            'params': ['device', 'vdom', 'explicit'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit/{explicit}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webproxy_explicit_pacpolicy': {
            'params': ['device', 'vdom', 'pac-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit/pac-policy/{pac-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webproxy_explicitproxy': {
            'params': ['device', 'vdom', 'explicit-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit-proxy/{explicit-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_fastfallback': {
            'params': ['device', 'vdom', 'fast-fallback'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/fast-fallback/{fast-fallback}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'webproxy_forwardserver': {
            'params': ['device', 'vdom', 'forward-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/forward-server/{forward-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_forwardservergroup': {
            'params': ['device', 'vdom', 'forward-server-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/forward-server-group/{forward-server-group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_forwardservergroup_serverlist': {
            'params': ['device', 'vdom', 'forward-server-group', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/forward-server-group/{forward-server-group}/server-list/{server-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_implicitproxyrule': {
            'params': ['device', 'vdom', 'implicit-proxy-rule'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/implicit-proxy-rule/{implicit-proxy-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_implicitproxyrule_proxyservers': {
            'params': ['device', 'vdom', 'implicit-proxy-rule', 'proxy-servers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/implicit-proxy-rule/{implicit-proxy-rule}/proxy-servers/{proxy-servers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_implicitproxysetting': {
            'params': ['device', 'vdom', 'implicit-proxy-setting'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/implicit-proxy-setting/{implicit-proxy-setting}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_isolatorserver': {
            'params': ['device', 'vdom', 'isolator-server'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/isolator-server/{isolator-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_pacpolicy': {
            'params': ['device', 'vdom', 'pac-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/pac-policy/{pac-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_profile': {
            'params': ['device', 'vdom', 'profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_profile_headers': {
            'params': ['device', 'vdom', 'profile', 'headers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/profile/{profile}/headers/{headers}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_redirectprofile': {
            'params': ['device', 'vdom', 'redirect-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/redirect-profile/{redirect-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_redirectprofile_entries': {
            'params': ['device', 'vdom', 'redirect-profile', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/redirect-profile/{redirect-profile}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_urllist': {
            'params': ['device', 'vdom', 'url-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-list/{url-list}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_urllist_entries': {
            'params': ['device', 'vdom', 'url-list', 'entries'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-list/{url-list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'webproxy_urlmatch': {
            'params': ['device', 'vdom', 'url-match'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-match/{url-match}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'webproxy_wisp': {
            'params': ['device', 'vdom', 'wisp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/wisp/{wisp}'
            ],
            'mkey': 'name', 'v_range': [['7.4.8', '7.4.10'], ['7.6.4', '']]
        },
        'wireless_accesscontrollist': {
            'params': ['device', 'vdom', 'access-control-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['device', 'vdom', 'access-control-list', 'layer3-ipv4-rules'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'mkey': 'rule_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['device', 'vdom', 'access-control-list', 'layer3-ipv6-rules'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'mkey': 'rule_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile': {
            'params': ['device', 'vdom', 'apcfg-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile_commandlist': {
            'params': ['device', 'vdom', 'apcfg-profile', 'command-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_apstatus': {
            'params': ['device', 'vdom', 'ap-status'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ap-status/{ap-status}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_arrpprofile': {
            'params': ['device', 'vdom', 'arrp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_bleprofile': {
            'params': ['device', 'vdom', 'ble-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ble-profile/{ble-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile': {
            'params': ['device', 'vdom', 'bonjour-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqp3gppcellular': {
            'params': ['device', 'vdom', 'anqp-3gpp-cellular'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqp3gppcellular_mccmnclist': {
            'params': ['device', 'vdom', 'anqp-3gpp-cellular', 'mcc-mnc-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpipaddresstype': {
            'params': ['device', 'vdom', 'anqp-ip-address-type'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm': {
            'params': ['device', 'vdom', 'anqp-nai-realm'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist': {
            'params': ['device', 'vdom', 'anqp-nai-realm', 'nai-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': ['device', 'vdom', 'anqp-nai-realm', 'nai-list', 'eap-method'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}'
            ],
            'mkey': 'index', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': ['device', 'vdom', 'anqp-nai-realm', 'nai-list', 'eap-method', 'auth-param'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}/auth-param/{auth-param}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnetworkauthtype': {
            'params': ['device', 'vdom', 'anqp-network-auth-type'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqproamingconsortium': {
            'params': ['device', 'vdom', 'anqp-roaming-consortium'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenuename': {
            'params': ['device', 'vdom', 'anqp-venue-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenueurl': {
            'params': ['device', 'vdom', 'anqp-venue-url'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge': {
            'params': ['device', 'vdom', 'h2qp-advice-of-charge'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge_aoclist': {
            'params': ['device', 'vdom', 'h2qp-advice-of-charge', 'aoc-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': ['device', 'vdom', 'h2qp-advice-of-charge', 'aoc-list', 'plan-info'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-'
                'info/{plan-info}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpconncapability': {
            'params': ['device', 'vdom', 'h2qp-conn-capability'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpoperatorname': {
            'params': ['device', 'vdom', 'h2qp-operator-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider': {
            'params': ['device', 'vdom', 'h2qp-osu-provider'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider_friendlyname': {
            'params': ['device', 'vdom', 'h2qp-osu-provider', 'friendly-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ],
            'mkey': 'index', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider_servicedescription': {
            'params': ['device', 'vdom', 'h2qp-osu-provider', 'service-description'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-desc'
                'ription}'
            ],
            'mkey': 'service_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovidernai': {
            'params': ['device', 'vdom', 'h2qp-osu-provider-nai'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovidernai_nailist': {
            'params': ['device', 'vdom', 'h2qp-osu-provider-nai', 'nai-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qptermsandconditions': {
            'params': ['device', 'vdom', 'h2qp-terms-and-conditions'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpwanmetric': {
            'params': ['device', 'vdom', 'h2qp-wan-metric'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_hsprofile': {
            'params': ['device', 'vdom', 'hs-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_icon': {
            'params': ['device', 'vdom', 'icon'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_icon_iconlist': {
            'params': ['device', 'vdom', 'icon', 'icon-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap': {
            'params': ['device', 'vdom', 'qos-map'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap_dscpexcept': {
            'params': ['device', 'vdom', 'qos-map', 'dscp-except'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ],
            'mkey': 'index', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap_dscprange': {
            'params': ['device', 'vdom', 'qos-map', 'dscp-range'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ],
            'mkey': 'index', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_intercontroller_intercontrollerpeer': {
            'params': ['device', 'inter-controller-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wireless-controller/inter-controller/inter-controller-peer/{inter-controller-peer}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_lwprofile': {
            'params': ['device', 'vdom', 'lw-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/lw-profile/{lw-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.6.5', '']]
        },
        'wireless_mpskprofile': {
            'params': ['device', 'vdom', 'mpsk-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup': {
            'params': ['device', 'vdom', 'mpsk-profile', 'mpsk-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup_mpskkey': {
            'params': ['device', 'vdom', 'mpsk-profile', 'mpsk-group', 'mpsk-key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_nacprofile': {
            'params': ['device', 'vdom', 'nac-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/nac-profile/{nac-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_qosprofile': {
            'params': ['device', 'vdom', 'qos-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/qos-profile/{qos-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_region': {
            'params': ['device', 'vdom', 'region'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/region/{region}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_setting_offendingssid': {
            'params': ['device', 'vdom', 'offending-ssid'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/setting/offending-ssid/{offending-ssid}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_snmp_community': {
            'params': ['device', 'vdom', 'community'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_snmp_community_hosts': {
            'params': ['device', 'vdom', 'community', 'hosts'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_snmp_community_hosts6': {
            'params': ['device', 'vdom', 'community', 'hosts6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'mkey': 'id', 'v_range': [['7.6.5', '']]
        },
        'wireless_snmp_user': {
            'params': ['device', 'vdom', 'user'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/user/{user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_ssidpolicy': {
            'params': ['device', 'vdom', 'ssid-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ssid-policy/{ssid-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_syslogprofile': {
            'params': ['device', 'vdom', 'syslog-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/syslog-profile/{syslog-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_utmprofile': {
            'params': ['device', 'vdom', 'utm-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/utm-profile/{utm-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_vap': {
            'params': ['device', 'vdom', 'vap'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_vap_macfilterlist': {
            'params': ['device', 'vdom', 'vap', 'mac-filter-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_vap_vlanname': {
            'params': ['device', 'vdom', 'vap', 'vlan-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_vap_vlanpool': {
            'params': ['device', 'vdom', 'vap', 'vlan-pool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_vapgroup': {
            'params': ['device', 'vdom', 'vap-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap-group/{vap-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wagprofile': {
            'params': ['device', 'vdom', 'wag-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wag-profile/{wag-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_widsprofile': {
            'params': ['device', 'vdom', 'wids-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wids-profile/{wids-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtp': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}'
            ],
            'mkey': 'wtp_id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtp_splittunnelingacl': {
            'params': ['device', 'vdom', 'wtp', 'split-tunneling-acl'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtpgroup': {
            'params': ['device', 'vdom', 'wtp-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-group/{wtp-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtpprofile': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_denymaclist': {
            'params': ['device', 'vdom', 'wtp-profile', 'deny-mac-list'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_splittunnelingacl': {
            'params': ['device', 'vdom', 'wtp-profile', 'split-tunneling-acl'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.12'], ['7.4.3', '']]
        },
        'ztna_reverseconnector': {
            'params': ['device', 'vdom', 'reverse-connector'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/reverse-connector/{reverse-connector}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'ztna_serviceconnector': {
            'params': ['device', 'vdom', 'service-connector'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/service-connector/{service-connector}'
            ],
            'mkey': 'name', 'v_range': [['7.6.4', '']]
        },
        'ztna_trafficforwardproxy': {
            'params': ['device', 'vdom', 'traffic-forward-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxyreverseservice_remoteservers': {
            'params': ['device', 'vdom', 'remote-servers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy-reverse-service/remote-servers/{remote-servers}'
            ],
            'mkey': 'name', 'v_range': [['7.6.0', '']]
        },
        'ztna_webportal': {
            'params': ['device', 'vdom', 'web-portal'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal/{web-portal}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'ztna_webportalbookmark': {
            'params': ['device', 'vdom', 'web-portal-bookmark'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark/{web-portal-bookmark}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'ztna_webportalbookmark_bookmarks': {
            'params': ['device', 'vdom', 'web-portal-bookmark', 'bookmarks'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-portal-bookmark/{web-portal-bookmark}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy': {
            'params': ['device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway': {
            'params': ['device', 'vdom', 'web-proxy', 'api-gateway'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6': {
            'params': ['device', 'vdom', 'web-proxy', 'api-gateway6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6_realservers': {
            'params': ['device', 'vdom', 'web-proxy', 'api-gateway6', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway_realservers': {
            'params': ['device', 'vdom', 'web-proxy', 'api-gateway', 'realservers'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        }
    }

    module_arg_spec = {
        'access_token': {'type': 'str', 'no_log': True},
        'enable_log': {'type': 'bool', 'default': False},
        'forticloud_access_token': {'type': 'str', 'no_log': True},
        'workspace_locking_adom': {'type': 'str'},
        'workspace_locking_timeout': {'type': 'int', 'default': 300},
        'rc_succeeded': {'type': 'list', 'elements': 'int'},
        'rc_failed': {'type': 'list', 'elements': 'int'},
        'rename': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(rename_metadata.keys())
                },
                'self': {'required': True, 'type': 'dict'},
                'target': {'required': True, 'type': 'dict'}
            }
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec, supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgd = NAPIManager('rename', rename_metadata, None, None, None, module, connection)
    fmgd.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
