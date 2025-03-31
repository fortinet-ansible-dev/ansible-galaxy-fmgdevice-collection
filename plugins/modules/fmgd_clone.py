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
module: fmgd_clone
short_description: Clone an object in FortiManager.
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
        required: false
        type: str
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Access token of FortiCloud managed API users, this option is available with FortiManager later than 6.4.0.
        required: false
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other users to release workspace lock.
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
    clone:
        description: Clone An Object.
        type: dict
        required: true
        suboptions:
            selector:
                required: true
                description: Selector of the clone object.
                type: str
                choices:
                    - 'antivirus_exemptlist'
                    - 'aws_vpce'
                    - 'azure_vwaningresspublicips'
                    - 'azure_vwanslb_permanentsecurityrules_rules'
                    - 'azure_vwanslb_temporarysecurityrules_rules'
                    - 'casb_attributematch'
                    - 'casb_attributematch_attribute'
                    - 'certificate_remote'
                    - 'dlp_exactdatamatch'
                    - 'dlp_exactdatamatch_columns'
                    - 'dlp_fpdocsource'
                    - 'endpointcontrol_fctemsoverride'
                    - 'ethernetoam_cfm'
                    - 'ethernetoam_cfm_service'
                    - 'extendercontroller_extender'
                    - 'extensioncontroller_extender'
                    - 'extensioncontroller_extendervap'
                    - 'extensioncontroller_fortigate'
                    - 'extensioncontroller_fortigateprofile'
                    - 'firewall_accessproxysshclientcert'
                    - 'firewall_accessproxysshclientcert_certextension'
                    - 'firewall_dnstranslation'
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
                    - 'firewall_ipmacbinding_table'
                    - 'firewall_iptranslation'
                    - 'firewall_ondemandsniffer'
                    - 'firewall_pfcp'
                    - 'firewall_policy'
                    - 'firewall_sniffer'
                    - 'firewall_sniffer_anomaly'
                    - 'firewall_ssh_hostkey'
                    - 'firewall_ssh_localkey'
                    - 'firewall_sslserver'
                    - 'firewall_ttlpolicy'
                    - 'gtp_apnshaper'
                    - 'gtp_ieallowlist'
                    - 'gtp_ieallowlist_entries'
                    - 'gtp_rattimeoutprofile'
                    - 'icap_profile'
                    - 'icap_server'
                    - 'icap_servergroup'
                    - 'icap_servergroup_serverlist'
                    - 'loadbalance_flowrule'
                    - 'loadbalance_setting_workers'
                    - 'loadbalance_workergroup'
                    - 'log_azuresecuritycenter2_filter_freestyle'
                    - 'log_azuresecuritycenter2_setting_customfieldname'
                    - 'log_azuresecuritycenter_filter_freestyle'
                    - 'log_azuresecuritycenter_setting_customfieldname'
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
                    - 'log_syslogd2_setting_customfieldname'
                    - 'log_syslogd3_filter_freestyle'
                    - 'log_syslogd3_overridefilter_freestyle'
                    - 'log_syslogd3_overridesetting_customfieldname'
                    - 'log_syslogd3_setting_customfieldname'
                    - 'log_syslogd4_filter_freestyle'
                    - 'log_syslogd4_overridefilter_freestyle'
                    - 'log_syslogd4_overridesetting_customfieldname'
                    - 'log_syslogd4_setting_customfieldname'
                    - 'log_syslogd_filter_freestyle'
                    - 'log_syslogd_overridefilter_freestyle'
                    - 'log_syslogd_overridesetting_customfieldname'
                    - 'log_syslogd_setting_customfieldname'
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
                    - 'router_authpath'
                    - 'router_bfd6_multihoptemplate'
                    - 'router_bfd6_neighbor'
                    - 'router_bfd_multihoptemplate'
                    - 'router_bfd_neighbor'
                    - 'router_bgp_admindistance'
                    - 'router_bgp_aggregateaddress'
                    - 'router_bgp_aggregateaddress6'
                    - 'router_bgp_neighbor'
                    - 'router_bgp_neighbor_conditionaladvertise'
                    - 'router_bgp_neighbor_conditionaladvertise6'
                    - 'router_bgp_neighborgroup'
                    - 'router_bgp_neighborrange'
                    - 'router_bgp_neighborrange6'
                    - 'router_bgp_network'
                    - 'router_bgp_network6'
                    - 'router_bgp_vrf'
                    - 'router_bgp_vrf6'
                    - 'router_bgp_vrf6_leaktarget'
                    - 'router_bgp_vrf_leaktarget'
                    - 'router_bgp_vrfleak'
                    - 'router_bgp_vrfleak6'
                    - 'router_bgp_vrfleak6_target'
                    - 'router_bgp_vrfleak_target'
                    - 'router_extcommunitylist'
                    - 'router_extcommunitylist_rule'
                    - 'router_isis_isisinterface'
                    - 'router_isis_isisnet'
                    - 'router_isis_summaryaddress'
                    - 'router_isis_summaryaddress6'
                    - 'router_keychain'
                    - 'router_keychain_key'
                    - 'router_multicast6_interface'
                    - 'router_multicast6_pimsmglobal_rpaddress'
                    - 'router_multicast_interface'
                    - 'router_multicast_interface_joingroup'
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
                    - 'router_ospf_summaryaddress'
                    - 'router_policy'
                    - 'router_policy6'
                    - 'router_rip_distance'
                    - 'router_rip_distributelist'
                    - 'router_rip_interface'
                    - 'router_rip_neighbor'
                    - 'router_rip_network'
                    - 'router_rip_offsetlist'
                    - 'router_ripng_aggregateaddress'
                    - 'router_ripng_distance'
                    - 'router_ripng_distributelist'
                    - 'router_ripng_interface'
                    - 'router_ripng_neighbor'
                    - 'router_ripng_network'
                    - 'router_ripng_offsetlist'
                    - 'router_routemap'
                    - 'router_static'
                    - 'router_static6'
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
                    - 'switchcontroller_managedswitch_ports'
                    - 'switchcontroller_managedswitch_ports_dhcpsnoopoption82override'
                    - 'switchcontroller_managedswitch_remotelog'
                    - 'switchcontroller_managedswitch_routeoffloadrouter'
                    - 'switchcontroller_managedswitch_snmpcommunity'
                    - 'switchcontroller_managedswitch_snmpcommunity_hosts'
                    - 'switchcontroller_managedswitch_snmpuser'
                    - 'switchcontroller_managedswitch_staticmac'
                    - 'switchcontroller_managedswitch_stpinstance'
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
                    - 'system_affinityinterrupt'
                    - 'system_affinitypacketredistribution'
                    - 'system_alias'
                    - 'system_apiuser'
                    - 'system_apiuser_trusthost'
                    - 'system_arptable'
                    - 'system_automationaction'
                    - 'system_automationaction_httpheaders'
                    - 'system_automationcondition'
                    - 'system_automationdestination'
                    - 'system_automationstitch'
                    - 'system_automationstitch_actions'
                    - 'system_automationtrigger'
                    - 'system_automationtrigger_fields'
                    - 'system_autoscript'
                    - 'system_centralmanagement_serverlist'
                    - 'system_clustersync'
                    - 'system_clustersync_sessionsyncfilter_customservice'
                    - 'system_consoleserver_entries'
                    - 'system_csf_fabricconnector'
                    - 'system_csf_fabricdevice'
                    - 'system_csf_trustedlist'
                    - 'system_ddns'
                    - 'system_deviceupgrade'
                    - 'system_deviceupgrade_knownhamembers'
                    - 'system_dhcp6_server'
                    - 'system_dhcp6_server_iprange'
                    - 'system_dhcp6_server_options'
                    - 'system_dhcp6_server_prefixrange'
                    - 'system_dnsdatabase'
                    - 'system_dnsdatabase_dnsentry'
                    - 'system_dnsserver'
                    - 'system_dscpbasedpriority'
                    - 'system_evpn'
                    - 'system_fabricvpn_advertisedsubnets'
                    - 'system_fabricvpn_overlays'
                    - 'system_federatedupgrade_knownhamembers'
                    - 'system_federatedupgrade_nodelist'
                    - 'system_geneve'
                    - 'system_gretunnel'
                    - 'system_ha_hamgmtinterfaces'
                    - 'system_ha_unicastpeers'
                    - 'system_ha_vcluster'
                    - 'system_healthcheckfortiguard'
                    - 'system_interface'
                    - 'system_interface_clientoptions'
                    - 'system_interface_dhcpsnoopingserverlist'
                    - 'system_interface_ipv6_clientoptions'
                    - 'system_interface_ipv6_dhcp6iapdlist'
                    - 'system_interface_ipv6_ip6delegatedprefixlist'
                    - 'system_interface_ipv6_ip6dnssllist'
                    - 'system_interface_ipv6_ip6extraaddr'
                    - 'system_interface_ipv6_ip6prefixlist'
                    - 'system_interface_ipv6_ip6rdnsslist'
                    - 'system_interface_ipv6_ip6routelist'
                    - 'system_interface_ipv6_vrrp6'
                    - 'system_interface_secondaryip'
                    - 'system_interface_tagging'
                    - 'system_interface_vrrp'
                    - 'system_interface_vrrp_proxyarp'
                    - 'system_interface_wifinetworks'
                    - 'system_ipam_pools'
                    - 'system_ipam_pools_exclude'
                    - 'system_ipam_rules'
                    - 'system_ipiptunnel'
                    - 'system_ipsecaggregate'
                    - 'system_ipsurlfilterdns'
                    - 'system_ipsurlfilterdns6'
                    - 'system_ipv6neighborcache'
                    - 'system_ipv6tunnel'
                    - 'system_iscsi'
                    - 'system_isfqueueprofile'
                    - 'system_linkmonitor'
                    - 'system_linkmonitor_serverlist'
                    - 'system_lldp_networkpolicy'
                    - 'system_ltemodem_dataplan'
                    - 'system_macaddresstable'
                    - 'system_mobiletunnel'
                    - 'system_mobiletunnel_network'
                    - 'system_nat64_secondaryprefix'
                    - 'system_netflow_collectors'
                    - 'system_netflow_exclusionfilters'
                    - 'system_np6'
                    - 'system_np6xlite'
                    - 'system_npupost_portnpumap'
                    - 'system_npuvlink'
                    - 'system_ntp_ntpserver'
                    - 'system_pcpserver_pools'
                    - 'system_physicalswitch'
                    - 'system_pppoeinterface'
                    - 'system_proxyarp'
                    - 'system_ptp_serverinterface'
                    - 'system_saml_serviceproviders'
                    - 'system_saml_serviceproviders_assertionattributes'
                    - 'system_sdnvpn'
                    - 'system_sdwan_duplication'
                    - 'system_sdwan_healthcheck'
                    - 'system_sdwan_healthcheck_sla'
                    - 'system_sdwan_healthcheckfortiguard'
                    - 'system_sdwan_healthcheckfortiguard_sla'
                    - 'system_sdwan_members'
                    - 'system_sdwan_neighbor'
                    - 'system_sdwan_service'
                    - 'system_sdwan_service_sla'
                    - 'system_sdwan_zone'
                    - 'system_securityrating_controls'
                    - 'system_sessionhelper'
                    - 'system_sessionttl_port'
                    - 'system_sflow_collectors'
                    - 'system_sittunnel'
                    - 'system_smcntp_ntpserver'
                    - 'system_snmp_community'
                    - 'system_snmp_community_hosts'
                    - 'system_snmp_community_hosts6'
                    - 'system_snmp_mibview'
                    - 'system_snmp_rmonstat'
                    - 'system_snmp_user'
                    - 'system_speedtestschedule'
                    - 'system_speedtestserver'
                    - 'system_speedtestserver_host'
                    - 'system_splitportmode'
                    - 'system_ssoadmin'
                    - 'system_ssoforticloudadmin'
                    - 'system_ssofortigatecloudadmin'
                    - 'system_standalonecluster_clusterpeer'
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
                    - 'system_virtualwanlink_members'
                    - 'system_virtualwanlink_neighbor'
                    - 'system_virtualwanlink_service'
                    - 'system_virtualwanlink_service_sla'
                    - 'system_vneinterface'
                    - 'system_vpce'
                    - 'system_vxlan'
                    - 'system_wccp'
                    - 'system_wireless_apstatus'
                    - 'system_zone'
                    - 'system_zone_tagging'
                    - 'user_nacpolicy'
                    - 'user_quarantine_targets'
                    - 'user_quarantine_targets_macs'
                    - 'user_scim'
                    - 'user_setting_authports'
                    - 'videofilter_youtubekey'
                    - 'vpn_certificate_crl'
                    - 'vpn_certificate_local'
                    - 'vpn_ipsec_concentrator'
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
                    - 'vpnsslweb_userbookmark'
                    - 'vpnsslweb_userbookmark_bookmarks'
                    - 'vpnsslweb_userbookmark_bookmarks_formdata'
                    - 'vpnsslweb_usergroupbookmark'
                    - 'vpnsslweb_usergroupbookmark_bookmarks'
                    - 'vpnsslweb_usergroupbookmark_bookmarks_formdata'
                    - 'wanopt_cacheservice_dstpeer'
                    - 'wanopt_cacheservice_srcpeer'
                    - 'wanopt_contentdeliverynetworkrule'
                    - 'wanopt_contentdeliverynetworkrule_rules'
                    - 'wanopt_contentdeliverynetworkrule_rules_matchentries'
                    - 'wanopt_contentdeliverynetworkrule_rules_skipentries'
                    - 'webfilter_ftgdlocalrisk'
                    - 'webfilter_ftgdrisklevel'
                    - 'webfilter_override'
                    - 'webfilter_searchengine'
                    - 'webproxy_debugurl'
                    - 'webproxy_explicit_pacpolicy'
                    - 'webproxy_fastfallback'
                    - 'webproxy_urlmatch'
                    - 'wireless_accesscontrollist'
                    - 'wireless_accesscontrollist_layer3ipv4rules'
                    - 'wireless_accesscontrollist_layer3ipv6rules'
                    - 'wireless_apcfgprofile'
                    - 'wireless_apcfgprofile_commandlist'
                    - 'wireless_apstatus'
                    - 'wireless_arrpprofile'
                    - 'wireless_bleprofile'
                    - 'wireless_bonjourprofile'
                    - 'wireless_bonjourprofile_policylist'
                    - 'wireless_hotspot20_anqp3gppcellular'
                    - 'wireless_hotspot20_anqp3gppcellular_mccmnclist'
                    - 'wireless_hotspot20_anqpipaddresstype'
                    - 'wireless_hotspot20_anqpnairealm'
                    - 'wireless_hotspot20_anqpnairealm_nailist'
                    - 'wireless_hotspot20_anqpnairealm_nailist_eapmethod'
                    - 'wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam'
                    - 'wireless_hotspot20_anqpnetworkauthtype'
                    - 'wireless_hotspot20_anqproamingconsortium'
                    - 'wireless_hotspot20_anqproamingconsortium_oilist'
                    - 'wireless_hotspot20_anqpvenuename'
                    - 'wireless_hotspot20_anqpvenuename_valuelist'
                    - 'wireless_hotspot20_anqpvenueurl'
                    - 'wireless_hotspot20_anqpvenueurl_valuelist'
                    - 'wireless_hotspot20_h2qpadviceofcharge'
                    - 'wireless_hotspot20_h2qpadviceofcharge_aoclist'
                    - 'wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo'
                    - 'wireless_hotspot20_h2qpconncapability'
                    - 'wireless_hotspot20_h2qpoperatorname'
                    - 'wireless_hotspot20_h2qpoperatorname_valuelist'
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
                    - 'wireless_mpskprofile'
                    - 'wireless_mpskprofile_mpskgroup'
                    - 'wireless_mpskprofile_mpskgroup_mpskkey'
                    - 'wireless_nacprofile'
                    - 'wireless_qosprofile'
                    - 'wireless_region'
                    - 'wireless_setting_offendingssid'
                    - 'wireless_snmp_community'
                    - 'wireless_snmp_community_hosts'
                    - 'wireless_snmp_user'
                    - 'wireless_ssidpolicy'
                    - 'wireless_syslogprofile'
                    - 'wireless_utmprofile'
                    - 'wireless_vap'
                    - 'wireless_vap_macfilterlist'
                    - 'wireless_vap_mpskkey'
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
                    - 'ztna_trafficforwardproxy'
                    - 'ztna_trafficforwardproxy_sslciphersuites'
                    - 'ztna_trafficforwardproxy_sslserverciphersuites'
                    - 'ztna_trafficforwardproxyreverseservice_remoteservers'
                    - 'ztna_webportal'
                    - 'ztna_webportalbookmark'
                    - 'ztna_webportalbookmark_bookmarks'
                    - 'ztna_webproxy'
                    - 'ztna_webproxy_apigateway'
                    - 'ztna_webproxy_apigateway6'
                    - 'ztna_webproxy_apigateway6_realservers'
                    - 'ztna_webproxy_apigateway6_sslciphersuites'
                    - 'ztna_webproxy_apigateway_realservers'
                    - 'ztna_webproxy_apigateway_sslciphersuites'
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
- name: Clone an object
  hosts: fortimanagers
  connection: httpapi
  vars:
    device_name: "FGVMMLTM23001052"
    vdom_name: "root"
  tasks:
    - name: Clone an object
      fortinet.fmgdevice.fmgd_clone:
        clone:
          selector: "antivirus_exemptlist"
          self:
            device: "{{ device_name }}"
            vdom: "{{ vdom_name }}"
            exempt_list: "test2"
          target:
            name: "test3"
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
    clone_metadata = {
        'antivirus_exemptlist': {
            'params': ['device', 'exempt-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/antivirus/exempt-list/{exempt-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'aws_vpce': {
            'params': ['device', 'vpce'],
            'urls': [
                '/pm/config/device/{device}/global/aws/vpce/{vpce}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
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
            'params': ['attribute-match', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'casb_attributematch_attribute': {
            'params': ['attribute', 'attribute-match', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/casb/attribute-match/{attribute-match}/attribute/{attribute}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'certificate_remote': {
            'params': ['device', 'remote'],
            'urls': [
                '/pm/config/device/{device}/global/certificate/remote/{remote}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'dlp_exactdatamatch': {
            'params': ['device', 'exact-data-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'dlp_exactdatamatch_columns': {
            'params': ['columns', 'device', 'exact-data-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/exact-data-match/{exact-data-match}/columns/{columns}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'dlp_fpdocsource': {
            'params': ['device', 'fp-doc-source', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/dlp/fp-doc-source/{fp-doc-source}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'endpointcontrol_fctemsoverride': {
            'params': ['device', 'fctems-override', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/endpoint-control/fctems-override/{fctems-override}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'ethernetoam_cfm': {
            'params': ['cfm', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ethernet-oam/cfm/{cfm}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'ethernetoam_cfm_service': {
            'params': ['cfm', 'device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ethernet-oam/cfm/{cfm}/service/{service}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'extendercontroller_extender': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extender-controller/extender/{extender}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_extender': {
            'params': ['device', 'extender', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender/{extender}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_extendervap': {
            'params': ['device', 'extender-vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/extender-vap/{extender-vap}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'extensioncontroller_fortigate': {
            'params': ['device', 'fortigate', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate/{fortigate}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'extensioncontroller_fortigateprofile': {
            'params': ['device', 'fortigate-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/extension-controller/fortigate-profile/{fortigate-profile}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_accessproxysshclientcert': {
            'params': ['access-proxy-ssh-client-cert', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9']]
        },
        'firewall_accessproxysshclientcert_certextension': {
            'params': ['access-proxy-ssh-client-cert', 'cert-extension', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/access-proxy-ssh-client-cert/{access-proxy-ssh-client-cert}/cert-extension/{cert-extension}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9']]
        },
        'firewall_dnstranslation': {
            'params': ['device', 'dnstranslation', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/dnstranslation/{dnstranslation}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition': {
            'params': ['device', 'internet-service-definition'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition_entry': {
            'params': ['device', 'entry', 'internet-service-definition'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetservicedefinition_entry_portrange': {
            'params': ['device', 'entry', 'internet-service-definition', 'port-range'],
            'urls': [
                '/pm/config/device/{device}/global/firewall/internet-service-definition/{internet-service-definition}/entry/{entry}/port-range/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension': {
            'params': ['device', 'internet-service-extension', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry_ip6range': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'ip6-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip6-ra'
                'nge/{ip6-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry_iprange': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'ip-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/ip-ran'
                'ge/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_disableentry_portrange': {
            'params': ['device', 'disable-entry', 'internet-service-extension', 'port-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/disable-entry/{disable-entry}/port-r'
                'ange/{port-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_entry': {
            'params': ['device', 'entry', 'internet-service-extension', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_internetserviceextension_entry_portrange': {
            'params': ['device', 'entry', 'internet-service-extension', 'port-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/internet-service-extension/{internet-service-extension}/entry/{entry}/port-range/{port-range'
                '}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ipmacbinding_table': {
            'params': ['device', 'table', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ipmacbinding/table/{table}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_iptranslation': {
            'params': ['device', 'ip-translation', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ip-translation/{ip-translation}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ondemandsniffer': {
            'params': ['device', 'on-demand-sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/on-demand-sniffer/{on-demand-sniffer}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'firewall_pfcp': {
            'params': ['device', 'pfcp', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/pfcp/{pfcp}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/policy/{policy}'
            ],
            'mkey': 'policyid'
        },
        'firewall_sniffer': {
            'params': ['device', 'sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_sniffer_anomaly': {
            'params': ['anomaly', 'device', 'sniffer', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/sniffer/{sniffer}/anomaly/{anomaly}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ssh_hostkey': {
            'params': ['device', 'host-key', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/host-key/{host-key}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ssh_localkey': {
            'params': ['device', 'local-key', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssh/local-key/{local-key}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_sslserver': {
            'params': ['device', 'ssl-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ssl-server/{ssl-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'firewall_ttlpolicy': {
            'params': ['device', 'ttl-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/firewall/ttl-policy/{ttl-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'gtp_apnshaper': {
            'params': ['apn-shaper', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/apn-shaper/{apn-shaper}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'gtp_ieallowlist': {
            'params': ['device', 'ie-allow-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '7.6.1']]
        },
        'gtp_ieallowlist_entries': {
            'params': ['device', 'entries', 'ie-allow-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/ie-allow-list/{ie-allow-list}/entries/{entries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.8'], ['7.4.3', '7.6.1']]
        },
        'gtp_rattimeoutprofile': {
            'params': ['device', 'rat-timeout-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/gtp/rat-timeout-profile/{rat-timeout-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'icap_profile': {
            'params': ['device', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/profile/{profile}'
            ],
            'mkey': 'name'
        },
        'icap_server': {
            'params': ['device', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server/{server}'
            ],
            'mkey': 'name'
        },
        'icap_servergroup': {
            'params': ['device', 'server-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group/{server-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'icap_servergroup_serverlist': {
            'params': ['device', 'server-group', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/icap/server-group/{server-group}/server-list/{server-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_flowrule': {
            'params': ['device', 'flow-rule'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/flow-rule/{flow-rule}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_setting_workers': {
            'params': ['device', 'workers'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/setting/workers/{workers}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'loadbalance_workergroup': {
            'params': ['device', 'worker-group'],
            'urls': [
                '/pm/config/device/{device}/global/load-balance/worker-group/{worker-group}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'log_azuresecuritycenter2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter2_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center2/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_azuresecuritycenter_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/azure-security-center/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_disk_filter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/disk/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer2/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer2_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer2/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer3/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer3_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer3/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzer_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortianalyzer-cloud/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortianalyzercloud_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortianalyzer-cloud/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/fortiguard/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_fortiguard_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/fortiguard/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_memory_filter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/memory/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_nulldevice_filter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/null-device/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd2/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd2_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd2/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd3/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd3_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd3/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd4/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd4_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd4/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_overridefilter_freestyle': {
            'params': ['device', 'free-style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_overridesetting_customfieldname': {
            'params': ['custom-field-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/log/syslogd/override-setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_syslogd_setting_customfieldname': {
            'params': ['custom-field-name', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/log/syslogd/setting/custom-field-name/{custom-field-name}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'log_webtrends_filter_freestyle': {
            'params': ['device', 'free-style'],
            'urls': [
                '/pm/config/device/{device}/global/log/webtrends/filter/free-style/{free-style}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsx_profile': {
            'params': ['device', 'profile'],
            'urls': [
                '/pm/config/device/{device}/global/nsx/profile/{profile}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsxt_servicechain': {
            'params': ['device', 'service-chain'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'nsxt_servicechain_serviceindex': {
            'params': ['device', 'service-chain', 'service-index'],
            'urls': [
                '/pm/config/device/{device}/global/nsxt/service-chain/{service-chain}/service-index/{service-index}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'pfcp_messagefilter': {
            'params': ['device', 'message-filter', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/pfcp/message-filter/{message-filter}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart': {
            'params': ['chart', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_column': {
            'params': ['chart', 'column', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_column_mapping': {
            'params': ['chart', 'column', 'device', 'mapping', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/column/{column}/mapping/{mapping}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_chart_drilldowncharts': {
            'params': ['chart', 'device', 'drill-down-charts', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/chart/{chart}/drill-down-charts/{drill-down-charts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_dataset': {
            'params': ['dataset', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_dataset_field': {
            'params': ['dataset', 'device', 'field', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/field/{field}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_dataset_parameters': {
            'params': ['dataset', 'device', 'parameters', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/dataset/{dataset}/parameters/{parameters}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout': {
            'params': ['device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem': {
            'params': ['body-item', 'device', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem_list': {
            'params': ['body-item', 'device', 'layout', 'list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/list/{list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_bodyitem_parameters': {
            'params': ['body-item', 'device', 'layout', 'parameters', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/body-item/{body-item}/parameters/{parameters}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_footer_footeritem': {
            'params': ['device', 'footer-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/footer/footer-item/{footer-item}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_layout_page_header_headeritem': {
            'params': ['device', 'header-item', 'layout', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/layout/{layout}/page/header/header-item/{header-item}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_style': {
            'params': ['device', 'style', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/style/{style}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'report_theme': {
            'params': ['device', 'theme', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/report/theme/{theme}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_authpath': {
            'params': ['auth-path', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/auth-path/{auth-path}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd6_multihoptemplate': {
            'params': ['device', 'multihop-template', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/multihop-template/{multihop-template}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd6_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd6/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd_multihoptemplate': {
            'params': ['device', 'multihop-template', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/multihop-template/{multihop-template}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bfd_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bfd/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_admindistance': {
            'params': ['admin-distance', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/admin-distance/{admin-distance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_aggregateaddress': {
            'params': ['aggregate-address', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address/{aggregate-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_aggregateaddress6': {
            'params': ['aggregate-address6', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/aggregate-address6/{aggregate-address6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighbor_conditionaladvertise': {
            'params': ['conditional-advertise', 'device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}/conditional-advertise/{conditional-advertise}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighbor_conditionaladvertise6': {
            'params': ['conditional-advertise6', 'device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor/{neighbor}/conditional-advertise6/{conditional-advertise6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighborgroup': {
            'params': ['device', 'neighbor-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-group/{neighbor-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighborrange': {
            'params': ['device', 'neighbor-range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range/{neighbor-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_neighborrange6': {
            'params': ['device', 'neighbor-range6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/neighbor-range6/{neighbor-range6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_network6': {
            'params': ['device', 'network6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/network6/{network6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf': {
            'params': ['device', 'vdom', 'vrf'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf/{vrf}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf6': {
            'params': ['device', 'vdom', 'vrf6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf6/{vrf6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf6_leaktarget': {
            'params': ['device', 'leak-target', 'vdom', 'vrf6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf6/{vrf6}/leak-target/{leak-target}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrf_leaktarget': {
            'params': ['device', 'leak-target', 'vdom', 'vrf'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf/{vrf}/leak-target/{leak-target}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak': {
            'params': ['device', 'vdom', 'vrf-leak'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak/{vrf-leak}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak6': {
            'params': ['device', 'vdom', 'vrf-leak6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak6/{vrf-leak6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak6_target': {
            'params': ['device', 'target', 'vdom', 'vrf-leak6'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak6/{vrf-leak6}/target/{target}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_bgp_vrfleak_target': {
            'params': ['device', 'target', 'vdom', 'vrf-leak'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/bgp/vrf-leak/{vrf-leak}/target/{target}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_extcommunitylist': {
            'params': ['device', 'extcommunity-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_extcommunitylist_rule': {
            'params': ['device', 'extcommunity-list', 'rule', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/extcommunity-list/{extcommunity-list}/rule/{rule}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_isisinterface': {
            'params': ['device', 'isis-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-interface/{isis-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_isisnet': {
            'params': ['device', 'isis-net', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/isis-net/{isis-net}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_summaryaddress': {
            'params': ['device', 'summary-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address/{summary-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_isis_summaryaddress6': {
            'params': ['device', 'summary-address6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/isis/summary-address6/{summary-address6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_keychain': {
            'params': ['device', 'key-chain', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_keychain_key': {
            'params': ['device', 'key', 'key-chain', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/key-chain/{key-chain}/key/{key}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast6_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast6_pimsmglobal_rpaddress': {
            'params': ['device', 'rp-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast6/pim-sm-global/rp-address/{rp-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_interface_joingroup': {
            'params': ['device', 'interface', 'join-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/interface/{interface}/join-group/{join-group}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobal_rpaddress': {
            'params': ['device', 'rp-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global/rp-address/{rp-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicast_pimsmglobalvrf': {
            'params': ['device', 'pim-sm-global-vrf', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'router_multicast_pimsmglobalvrf_rpaddress': {
            'params': ['device', 'pim-sm-global-vrf', 'rp-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast/pim-sm-global-vrf/{pim-sm-global-vrf}/rp-address/{rp-address}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'router_multicastflow': {
            'params': ['device', 'multicast-flow', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_multicastflow_flows': {
            'params': ['device', 'flows', 'multicast-flow', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/multicast-flow/{multicast-flow}/flows/{flows}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area': {
            'params': ['area', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_ipseckeys': {
            'params': ['area', 'device', 'ipsec-keys', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/ipsec-keys/{ipsec-keys}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_range': {
            'params': ['area', 'device', 'range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/range/{range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_virtuallink': {
            'params': ['area', 'device', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_area_virtuallink_ipseckeys': {
            'params': ['area', 'device', 'ipsec-keys', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/area/{area}/virtual-link/{virtual-link}/ipsec-keys/{ipsec-keys}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface': {
            'params': ['device', 'ospf6-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface_ipseckeys': {
            'params': ['device', 'ipsec-keys', 'ospf6-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/ipsec-keys/{ipsec-keys}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_ospf6interface_neighbor': {
            'params': ['device', 'neighbor', 'ospf6-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/ospf6-interface/{ospf6-interface}/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf6_summaryaddress': {
            'params': ['device', 'summary-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf6/summary-address/{summary-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area': {
            'params': ['area', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_filterlist': {
            'params': ['area', 'device', 'filter-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/filter-list/{filter-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_range': {
            'params': ['area', 'device', 'range', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/range/{range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_virtuallink': {
            'params': ['area', 'device', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_area_virtuallink_md5keys': {
            'params': ['area', 'device', 'md5-keys', 'vdom', 'virtual-link'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/area/{area}/virtual-link/{virtual-link}/md5-keys/{md5-keys}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_distributelist': {
            'params': ['device', 'distribute-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/distribute-list/{distribute-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/neighbor/{neighbor}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_ospfinterface': {
            'params': ['device', 'ospf-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_ospfinterface_md5keys': {
            'params': ['device', 'md5-keys', 'ospf-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/ospf-interface/{ospf-interface}/md5-keys/{md5-keys}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ospf_summaryaddress': {
            'params': ['device', 'summary-address', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ospf/summary-address/{summary-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy/{policy}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_policy6': {
            'params': ['device', 'policy6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/policy6/{policy6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_distance': {
            'params': ['device', 'distance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distance/{distance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_distributelist': {
            'params': ['device', 'distribute-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/distribute-list/{distribute-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/neighbor/{neighbor}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_rip_offsetlist': {
            'params': ['device', 'offset-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/rip/offset-list/{offset-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_aggregateaddress': {
            'params': ['aggregate-address', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/aggregate-address/{aggregate-address}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_distance': {
            'params': ['device', 'distance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distance/{distance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_distributelist': {
            'params': ['device', 'distribute-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/distribute-list/{distribute-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_interface': {
            'params': ['device', 'interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/interface/{interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/neighbor/{neighbor}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_network': {
            'params': ['device', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_ripng_offsetlist': {
            'params': ['device', 'offset-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/ripng/offset-list/{offset-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_routemap': {
            'params': ['device', 'route-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/route-map/{route-map}'
            ],
            'mkey': 'name', 'v_range': [['7.0.2', '']]
        },
        'router_static': {
            'params': ['device', 'static', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/static/{static}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'router_static6': {
            'params': ['device', 'static6', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/router/static6/{static6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_acl_group': {
            'params': ['device', 'group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/group/{group}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_acl_ingress': {
            'params': ['device', 'ingress', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/acl/ingress/{ingress}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_autoconfig_custom': {
            'params': ['custom', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_custom_switchbinding': {
            'params': ['custom', 'device', 'switch-binding', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/custom/{custom}/switch-binding/{switch-binding}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_autoconfig_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/auto-config/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_customcommand': {
            'params': ['custom-command', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/custom-command/{custom-command}',
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/global/custom-command/{custom-command}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dsl_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dsl/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy': {
            'params': ['device', 'dynamic-port-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_dynamicportpolicy_policy': {
            'params': ['device', 'dynamic-port-policy', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/dynamic-port-policy/{dynamic-port-policy}/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking_aggregates': {
            'params': ['aggregates', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/aggregates/{aggregates}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_flowtracking_collectors': {
            'params': ['collectors', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/flow-tracking/collectors/{collectors}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_fortilinksettings': {
            'params': ['device', 'fortilink-settings', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/fortilink-settings/{fortilink-settings}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_initialconfig_template': {
            'params': ['device', 'template', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/initial-config/template/{template}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile': {
            'params': ['device', 'lldp-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_customtlvs': {
            'params': ['custom-tlvs', 'device', 'lldp-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/custom-tlvs/{custom-tlvs}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_medlocationservice': {
            'params': ['device', 'lldp-profile', 'med-location-service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-location-service/{med-location-service}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_lldpprofile_mednetworkpolicy': {
            'params': ['device', 'lldp-profile', 'med-network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/lldp-profile/{lldp-profile}/med-network-policy/{med-network-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_location': {
            'params': ['device', 'location', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/location/{location}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_macpolicy': {
            'params': ['device', 'mac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/mac-policy/{mac-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch': {
            'params': ['device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}'
            ],
            'mkey': 'switch-id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_customcommand': {
            'params': ['custom-command', 'device', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/custom-command/{custom-command}'
            ],
            'mkey': None, 'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_dhcpsnoopingstaticclient': {
            'params': ['device', 'dhcp-snooping-static-client', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/dhcp-snooping-static-client/{dhcp-snooping-static-c'
                'lient}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_igmpsnooping_vlans': {
            'params': ['device', 'managed-switch', 'vdom', 'vlans'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/igmp-snooping/vlans/{vlans}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard': {
            'params': ['device', 'ip-source-guard', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ipsourceguard_bindingentry': {
            'params': ['binding-entry', 'device', 'ip-source-guard', 'managed-switch', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ip-source-guard/{ip-source-guard}/binding-entry/{bi'
                'nding-entry}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_mirror': {
            'params': ['device', 'managed-switch', 'mirror', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/mirror/{mirror}'
            ],
            'mkey': 'name', 'v_range': [['6.0.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ports': {
            'params': ['device', 'managed-switch', 'ports', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports/{ports}'
            ],
            'mkey': 'port-name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_ports_dhcpsnoopoption82override': {
            'params': ['device', 'dhcp-snoop-option82-override', 'managed-switch', 'ports', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/ports/{ports}/dhcp-snoop-option82-override/{dhcp-sn'
                'oop-option82-override}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_managedswitch_remotelog': {
            'params': ['device', 'managed-switch', 'remote-log', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/remote-log/{remote-log}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_routeoffloadrouter': {
            'params': ['device', 'managed-switch', 'route-offload-router', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/route-offload-router/{route-offload-router}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity': {
            'params': ['device', 'managed-switch', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpcommunity_hosts': {
            'params': ['device', 'hosts', 'managed-switch', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_snmpuser': {
            'params': ['device', 'managed-switch', 'snmp-user', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/snmp-user/{snmp-user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_staticmac': {
            'params': ['device', 'managed-switch', 'static-mac', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/static-mac/{static-mac}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_stpinstance': {
            'params': ['device', 'managed-switch', 'stp-instance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/stp-instance/{stp-instance}'
            ],
            'mkey': 'id', 'v_range': [['6.2.0', '6.2.0'], ['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_managedswitch_vlan': {
            'params': ['device', 'managed-switch', 'vdom', 'vlan'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/managed-switch/{managed-switch}/vlan/{vlan}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_nacdevice': {
            'params': ['device', 'nac-device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-device/{nac-device}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_nacsettings': {
            'params': ['device', 'nac-settings', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/nac-settings/{nac-settings}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_portpolicy': {
            'params': ['device', 'port-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/port-policy/{port-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_ptp_interfacepolicy': {
            'params': ['device', 'interface-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/interface-policy/{interface-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_ptp_policy': {
            'params': ['device', 'policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/policy/{policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_ptp_profile': {
            'params': ['device', 'profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/ptp/profile/{profile}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'switchcontroller_qos_dot1pmap': {
            'params': ['device', 'dot1p-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/dot1p-map/{dot1p-map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_ipdscpmap': {
            'params': ['device', 'ip-dscp-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_ipdscpmap_map': {
            'params': ['device', 'ip-dscp-map', 'map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/ip-dscp-map/{ip-dscp-map}/map/{map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_qospolicy': {
            'params': ['device', 'qos-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/qos-policy/{qos-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_queuepolicy': {
            'params': ['device', 'queue-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_qos_queuepolicy_cosqueue': {
            'params': ['cos-queue', 'device', 'queue-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/qos/queue-policy/{queue-policy}/cos-queue/{cos-queue}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_remotelog': {
            'params': ['device', 'remote-log', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/remote-log/{remote-log}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_securitypolicy_8021x': {
            'params': ['802-1X', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/802-1X/{802-1X}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_securitypolicy_localaccess': {
            'params': ['device', 'local-access', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/security-policy/local-access/{local-access}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpcommunity': {
            'params': ['device', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpcommunity_hosts': {
            'params': ['device', 'hosts', 'snmp-community', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-community/{snmp-community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_snmpuser': {
            'params': ['device', 'snmp-user', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/snmp-user/{snmp-user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_stormcontrolpolicy': {
            'params': ['device', 'storm-control-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/storm-control-policy/{storm-control-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_stpinstance': {
            'params': ['device', 'stp-instance', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/stp-instance/{stp-instance}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchgroup': {
            'params': ['device', 'switch-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-group/{switch-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchinterfacetag': {
            'params': ['device', 'switch-interface-tag', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-interface-tag/{switch-interface-tag}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_switchprofile': {
            'params': ['device', 'switch-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/switch-profile/{switch-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficpolicy': {
            'params': ['device', 'traffic-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-policy/{traffic-policy}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetip': {
            'params': ['device', 'target-ip', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-ip/{target-ip}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetmac': {
            'params': ['device', 'target-mac', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-mac/{target-mac}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_trafficsniffer_targetport': {
            'params': ['device', 'target-port', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/traffic-sniffer/target-port/{target-port}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_virtualportpool': {
            'params': ['device', 'vdom', 'virtual-port-pool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/virtual-port-pool/{virtual-port-pool}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'switchcontroller_vlanpolicy': {
            'params': ['device', 'vdom', 'vlan-policy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/switch-controller/vlan-policy/{vlan-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_3gmodem_custom': {
            'params': ['custom', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/3g-modem/custom/{custom}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_5gmodem_dataplan': {
            'params': ['data-plan', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/5g-modem/data-plan/{data-plan}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_accprofile': {
            'params': ['accprofile', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/accprofile/{accprofile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_acme_accounts': {
            'params': ['accounts', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/acme/accounts/{accounts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_admin': {
            'params': ['admin', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/admin/{admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_affinityinterrupt': {
            'params': ['affinity-interrupt', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/affinity-interrupt/{affinity-interrupt}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_affinitypacketredistribution': {
            'params': ['affinity-packet-redistribution', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/affinity-packet-redistribution/{affinity-packet-redistribution}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_alias': {
            'params': ['alias', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/alias/{alias}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_apiuser': {
            'params': ['api-user', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/api-user/{api-user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_apiuser_trusthost': {
            'params': ['api-user', 'device', 'trusthost'],
            'urls': [
                '/pm/config/device/{device}/global/system/api-user/{api-user}/trusthost/{trusthost}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_arptable': {
            'params': ['arp-table', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/arp-table/{arp-table}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationaction': {
            'params': ['automation-action', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationaction_httpheaders': {
            'params': ['automation-action', 'device', 'http-headers'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-action/{automation-action}/http-headers/{http-headers}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationcondition': {
            'params': ['automation-condition', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-condition/{automation-condition}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'system_automationdestination': {
            'params': ['automation-destination', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-destination/{automation-destination}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationstitch': {
            'params': ['automation-stitch', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationstitch_actions': {
            'params': ['actions', 'automation-stitch', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-stitch/{automation-stitch}/actions/{actions}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationtrigger': {
            'params': ['automation-trigger', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_automationtrigger_fields': {
            'params': ['automation-trigger', 'device', 'fields'],
            'urls': [
                '/pm/config/device/{device}/global/system/automation-trigger/{automation-trigger}/fields/{fields}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_autoscript': {
            'params': ['auto-script', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/auto-script/{auto-script}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_centralmanagement_serverlist': {
            'params': ['device', 'server-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/central-management/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_clustersync': {
            'params': ['cluster-sync', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_clustersync_sessionsyncfilter_customservice': {
            'params': ['cluster-sync', 'custom-service', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/cluster-sync/{cluster-sync}/session-sync-filter/custom-service/{custom-service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_consoleserver_entries': {
            'params': ['device', 'entries'],
            'urls': [
                '/pm/config/device/{device}/global/system/console-server/entries/{entries}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf_fabricconnector': {
            'params': ['device', 'fabric-connector'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/fabric-connector/{fabric-connector}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf_fabricdevice': {
            'params': ['device', 'fabric-device'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/fabric-device/{fabric-device}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_csf_trustedlist': {
            'params': ['device', 'trusted-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/csf/trusted-list/{trusted-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ddns': {
            'params': ['ddns', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/ddns/{ddns}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_deviceupgrade': {
            'params': ['device', 'device-upgrade'],
            'urls': [
                '/pm/config/device/{device}/global/system/device-upgrade/{device-upgrade}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_deviceupgrade_knownhamembers': {
            'params': ['device', 'device-upgrade', 'known-ha-members'],
            'urls': [
                '/pm/config/device/{device}/global/system/device-upgrade/{device-upgrade}/known-ha-members/{known-ha-members}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'system_dhcp6_server': {
            'params': ['device', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dhcp6_server_iprange': {
            'params': ['device', 'ip-range', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/ip-range/{ip-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dhcp6_server_options': {
            'params': ['device', 'options', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/options/{options}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_dhcp6_server_prefixrange': {
            'params': ['device', 'prefix-range', 'server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dhcp6/server/{server}/prefix-range/{prefix-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnsdatabase': {
            'params': ['device', 'dns-database', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnsdatabase_dnsentry': {
            'params': ['device', 'dns-database', 'dns-entry', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-database/{dns-database}/dns-entry/{dns-entry}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dnsserver': {
            'params': ['device', 'dns-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/dns-server/{dns-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_dscpbasedpriority': {
            'params': ['device', 'dscp-based-priority'],
            'urls': [
                '/pm/config/device/{device}/global/system/dscp-based-priority/{dscp-based-priority}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_evpn': {
            'params': ['device', 'evpn', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/evpn/{evpn}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_fabricvpn_advertisedsubnets': {
            'params': ['advertised-subnets', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn/advertised-subnets/{advertised-subnets}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_fabricvpn_overlays': {
            'params': ['device', 'overlays'],
            'urls': [
                '/pm/config/device/{device}/global/system/fabric-vpn/overlays/{overlays}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_federatedupgrade_knownhamembers': {
            'params': ['device', 'known-ha-members'],
            'urls': [
                '/pm/config/device/{device}/global/system/federated-upgrade/known-ha-members/{known-ha-members}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'system_federatedupgrade_nodelist': {
            'params': ['device', 'node-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/federated-upgrade/node-list/{node-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_geneve': {
            'params': ['device', 'geneve', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/geneve/{geneve}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_gretunnel': {
            'params': ['device', 'gre-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/gre-tunnel/{gre-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_hamgmtinterfaces': {
            'params': ['device', 'ha-mgmt-interfaces'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/ha-mgmt-interfaces/{ha-mgmt-interfaces}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_unicastpeers': {
            'params': ['device', 'unicast-peers'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/unicast-peers/{unicast-peers}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ha_vcluster': {
            'params': ['device', 'vcluster'],
            'urls': [
                '/pm/config/device/{device}/global/system/ha/vcluster/{vcluster}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
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
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_clientoptions': {
            'params': ['client-options', 'device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/client-options/{client-options}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_dhcpsnoopingserverlist': {
            'params': ['device', 'dhcp-snooping-server-list', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/dhcp-snooping-server-list/{dhcp-snooping-server-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_clientoptions': {
            'params': ['client-options', 'device', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/client-options/{client-options}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_interface_ipv6_dhcp6iapdlist': {
            'params': ['device', 'dhcp6-iapd-list', 'interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/dhcp6-iapd-list/{dhcp6-iapd-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6delegatedprefixlist': {
            'params': ['device', 'interface', 'ip6-delegated-prefix-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-delegated-prefix-list/{ip6-delegated-prefix-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6dnssllist': {
            'params': ['device', 'interface', 'ip6-dnssl-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-dnssl-list/{ip6-dnssl-list}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'system_interface_ipv6_ip6extraaddr': {
            'params': ['device', 'interface', 'ip6-extra-addr'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-extra-addr/{ip6-extra-addr}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6prefixlist': {
            'params': ['device', 'interface', 'ip6-prefix-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-prefix-list/{ip6-prefix-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_ipv6_ip6rdnsslist': {
            'params': ['device', 'interface', 'ip6-rdnss-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-rdnss-list/{ip6-rdnss-list}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'system_interface_ipv6_ip6routelist': {
            'params': ['device', 'interface', 'ip6-route-list'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/ip6-route-list/{ip6-route-list}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'system_interface_ipv6_vrrp6': {
            'params': ['device', 'interface', 'vrrp6'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/ipv6/vrrp6/{vrrp6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_secondaryip': {
            'params': ['device', 'interface', 'secondaryip'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/secondaryip/{secondaryip}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_tagging': {
            'params': ['device', 'interface', 'tagging'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_vrrp': {
            'params': ['device', 'interface', 'vrrp'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_vrrp_proxyarp': {
            'params': ['device', 'interface', 'proxy-arp', 'vrrp'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/vrrp/{vrrp}/proxy-arp/{proxy-arp}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_interface_wifinetworks': {
            'params': ['device', 'interface', 'wifi-networks'],
            'urls': [
                '/pm/config/device/{device}/global/system/interface/{interface}/wifi-networks/{wifi-networks}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipam_pools': {
            'params': ['device', 'pools'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/pools/{pools}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipam_pools_exclude': {
            'params': ['device', 'exclude', 'pools'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/pools/{pools}/exclude/{exclude}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'system_ipam_rules': {
            'params': ['device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/system/ipam/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipiptunnel': {
            'params': ['device', 'ipip-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipip-tunnel/{ipip-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipsecaggregate': {
            'params': ['device', 'ipsec-aggregate', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipsec-aggregate/{ipsec-aggregate}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipsurlfilterdns': {
            'params': ['device', 'ips-urlfilter-dns'],
            'urls': [
                '/pm/config/device/{device}/global/system/ips-urlfilter-dns/{ips-urlfilter-dns}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipsurlfilterdns6': {
            'params': ['device', 'ips-urlfilter-dns6'],
            'urls': [
                '/pm/config/device/{device}/global/system/ips-urlfilter-dns6/{ips-urlfilter-dns6}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipv6neighborcache': {
            'params': ['device', 'ipv6-neighbor-cache', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-neighbor-cache/{ipv6-neighbor-cache}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ipv6tunnel': {
            'params': ['device', 'ipv6-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/ipv6-tunnel/{ipv6-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_iscsi': {
            'params': ['device', 'iscsi'],
            'urls': [
                '/pm/config/device/{device}/global/system/iscsi/{iscsi}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_isfqueueprofile': {
            'params': ['device', 'isf-queue-profile'],
            'urls': [
                '/pm/config/device/{device}/global/system/isf-queue-profile/{isf-queue-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_linkmonitor': {
            'params': ['device', 'link-monitor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_linkmonitor_serverlist': {
            'params': ['device', 'link-monitor', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/link-monitor/{link-monitor}/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_lldp_networkpolicy': {
            'params': ['device', 'network-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/lldp/network-policy/{network-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ltemodem_dataplan': {
            'params': ['data-plan', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/lte-modem/data-plan/{data-plan}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'system_macaddresstable': {
            'params': ['device', 'mac-address-table', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mac-address-table/{mac-address-table}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_mobiletunnel': {
            'params': ['device', 'mobile-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_mobiletunnel_network': {
            'params': ['device', 'mobile-tunnel', 'network', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/mobile-tunnel/{mobile-tunnel}/network/{network}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_nat64_secondaryprefix': {
            'params': ['device', 'secondary-prefix', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/nat64/secondary-prefix/{secondary-prefix}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_netflow_collectors': {
            'params': ['collectors', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_netflow_exclusionfilters': {
            'params': ['device', 'exclusion-filters'],
            'urls': [
                '/pm/config/device/{device}/global/system/netflow/exclusion-filters/{exclusion-filters}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_np6': {
            'params': ['device', 'np6'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6/{np6}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_np6xlite': {
            'params': ['device', 'np6xlite'],
            'urls': [
                '/pm/config/device/{device}/global/system/np6xlite/{np6xlite}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_npupost_portnpumap': {
            'params': ['device', 'port-npu-map'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-post/port-npu-map/{port-npu-map}'
            ],
            'mkey': None, 'v_range': [['7.4.3', '']]
        },
        'system_npuvlink': {
            'params': ['device', 'npu-vlink'],
            'urls': [
                '/pm/config/device/{device}/global/system/npu-vlink/{npu-vlink}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ntp_ntpserver': {
            'params': ['device', 'ntpserver'],
            'urls': [
                '/pm/config/device/{device}/global/system/ntp/ntpserver/{ntpserver}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_pcpserver_pools': {
            'params': ['device', 'pools', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pcp-server/pools/{pools}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_physicalswitch': {
            'params': ['device', 'physical-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/physical-switch/{physical-switch}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_pppoeinterface': {
            'params': ['device', 'pppoe-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/pppoe-interface/{pppoe-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_proxyarp': {
            'params': ['device', 'proxy-arp', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/proxy-arp/{proxy-arp}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ptp_serverinterface': {
            'params': ['device', 'server-interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/ptp/server-interface/{server-interface}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_saml_serviceproviders': {
            'params': ['device', 'service-providers'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_saml_serviceproviders_assertionattributes': {
            'params': ['assertion-attributes', 'device', 'service-providers'],
            'urls': [
                '/pm/config/device/{device}/global/system/saml/service-providers/{service-providers}/assertion-attributes/{assertion-attributes}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdnvpn': {
            'params': ['device', 'sdn-vpn'],
            'urls': [
                '/pm/config/device/{device}/global/system/sdn-vpn/{sdn-vpn}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'system_sdwan_duplication': {
            'params': ['device', 'duplication', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/duplication/{duplication}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheck': {
            'params': ['device', 'health-check', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheck_sla': {
            'params': ['device', 'health-check', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_healthcheckfortiguard': {
            'params': ['device', 'health-check-fortiguard', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard/{health-check-fortiguard}'
            ],
            'mkey': None, 'v_range': [['7.6.0', '']]
        },
        'system_sdwan_healthcheckfortiguard_sla': {
            'params': ['device', 'health-check-fortiguard', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/health-check-fortiguard/{health-check-fortiguard}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'system_sdwan_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/members/{members}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/service/{service}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sdwan_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sdwan/zone/{zone}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_securityrating_controls': {
            'params': ['controls', 'device'],
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
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sessionttl_port': {
            'params': ['device', 'port', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/session-ttl/port/{port}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_sflow_collectors': {
            'params': ['collectors', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/sflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'system_sittunnel': {
            'params': ['device', 'sit-tunnel', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/sit-tunnel/{sit-tunnel}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_smcntp_ntpserver': {
            'params': ['device', 'ntpserver'],
            'urls': [
                '/pm/config/device/{device}/global/system/smc-ntp/ntpserver/{ntpserver}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_community': {
            'params': ['community', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_community_hosts': {
            'params': ['community', 'device', 'hosts'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_community_hosts6': {
            'params': ['community', 'device', 'hosts6'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/community/{community}/hosts6/{hosts6}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_snmp_mibview': {
            'params': ['device', 'mib-view'],
            'urls': [
                '/pm/config/device/{device}/global/system/snmp/mib-view/{mib-view}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
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
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestschedule': {
            'params': ['device', 'speed-test-schedule', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-schedule/{speed-test-schedule}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestserver': {
            'params': ['device', 'speed-test-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_speedtestserver_host': {
            'params': ['device', 'host', 'speed-test-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/speed-test-server/{speed-test-server}/host/{host}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_splitportmode': {
            'params': ['device', 'split-port-mode'],
            'urls': [
                '/pm/config/device/{device}/global/system/global/split-port-mode/{split-port-mode}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ssoadmin': {
            'params': ['device', 'sso-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-admin/{sso-admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ssoforticloudadmin': {
            'params': ['device', 'sso-forticloud-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-forticloud-admin/{sso-forticloud-admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_ssofortigatecloudadmin': {
            'params': ['device', 'sso-fortigate-cloud-admin'],
            'urls': [
                '/pm/config/device/{device}/global/system/sso-fortigate-cloud-admin/{sso-fortigate-cloud-admin}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster_clusterpeer': {
            'params': ['cluster-peer', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_standalonecluster_clusterpeer_sessionsyncfilter_customservice': {
            'params': ['cluster-peer', 'custom-service', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/standalone-cluster/cluster-peer/{cluster-peer}/session-sync-filter/custom-service/{custom-service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
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
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_switchinterface': {
            'params': ['device', 'switch-interface'],
            'urls': [
                '/pm/config/device/{device}/global/system/switch-interface/{switch-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_tosbasedpriority': {
            'params': ['device', 'tos-based-priority'],
            'urls': [
                '/pm/config/device/{device}/global/system/tos-based-priority/{tos-based-priority}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdom': {
            'params': ['device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom/{vdom}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomexception': {
            'params': ['device', 'vdom-exception'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-exception/{vdom-exception}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomlink': {
            'params': ['device', 'vdom-link'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-link/{vdom-link}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomnetflow_collectors': {
            'params': ['collectors', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/vdom-netflow/collectors/{collectors}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomproperty': {
            'params': ['device', 'vdom-property'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-property/{vdom-property}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomradiusserver': {
            'params': ['device', 'vdom-radius-server'],
            'urls': [
                '/pm/config/device/{device}/global/system/vdom-radius-server/{vdom-radius-server}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_vdomsflow_collectors': {
            'params': ['collectors', 'device', 'vdom'],
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
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualswitch_port': {
            'params': ['device', 'port', 'virtual-switch'],
            'urls': [
                '/pm/config/device/{device}/global/system/virtual-switch/{virtual-switch}/port/{port}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_healthcheck': {
            'params': ['device', 'health-check', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_healthcheck_sla': {
            'params': ['device', 'health-check', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/health-check/{health-check}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_members': {
            'params': ['device', 'members', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/members/{members}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_neighbor': {
            'params': ['device', 'neighbor', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/neighbor/{neighbor}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_service': {
            'params': ['device', 'service', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_virtualwanlink_service_sla': {
            'params': ['device', 'service', 'sla', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/virtual-wan-link/service/{service}/sla/{sla}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
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
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_wccp': {
            'params': ['device', 'vdom', 'wccp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/wccp/{wccp}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_wireless_apstatus': {
            'params': ['ap-status', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/system/wireless/ap-status/{ap-status}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_zone': {
            'params': ['device', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'system_zone_tagging': {
            'params': ['device', 'tagging', 'vdom', 'zone'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/system/zone/{zone}/tagging/{tagging}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_nacpolicy': {
            'params': ['device', 'nac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/nac-policy/{nac-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_quarantine_targets': {
            'params': ['device', 'targets', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets/{targets}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_quarantine_targets_macs': {
            'params': ['device', 'macs', 'targets', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/quarantine/targets/{targets}/macs/{macs}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'user_scim': {
            'params': ['device', 'scim', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/scim/{scim}'
            ],
            'mkey': 'id', 'v_range': [['7.6.0', '']]
        },
        'user_setting_authports': {
            'params': ['auth-ports', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/user/setting/auth-ports/{auth-ports}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'videofilter_youtubekey': {
            'params': ['device', 'vdom', 'youtube-key'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/videofilter/youtube-key/{youtube-key}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9']]
        },
        'vpn_certificate_crl': {
            'params': ['crl', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/crl/{crl}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_certificate_local': {
            'params': ['device', 'local', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/certificate/local/{local}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_concentrator': {
            'params': ['concentrator', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/concentrator/{concentrator}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_forticlient': {
            'params': ['device', 'forticlient', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/forticlient/{forticlient}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_manualkey': {
            'params': ['device', 'manualkey', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey/{manualkey}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_manualkeyinterface': {
            'params': ['device', 'manualkey-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/manualkey-interface/{manualkey-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1': {
            'params': ['device', 'phase1', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1_ipv4excluderange': {
            'params': ['device', 'ipv4-exclude-range', 'phase1', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1_ipv6excluderange': {
            'params': ['device', 'ipv6-exclude-range', 'phase1', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1/{phase1}/ipv6-exclude-range/{ipv6-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface': {
            'params': ['device', 'phase1-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface_ipv4excluderange': {
            'params': ['device', 'ipv4-exclude-range', 'phase1-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv4-exclude-range/{ipv4-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase1interface_ipv6excluderange': {
            'params': ['device', 'ipv6-exclude-range', 'phase1-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase1-interface/{phase1-interface}/ipv6-exclude-range/{ipv6-exclude-range}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase2': {
            'params': ['device', 'phase2', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2/{phase2}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ipsec_phase2interface': {
            'params': ['device', 'phase2-interface', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ipsec/phase2-interface/{phase2-interface}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_kmipserver': {
            'params': ['device', 'kmip-server', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'vpn_kmipserver_serverlist': {
            'params': ['device', 'kmip-server', 'server-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/kmip-server/{kmip-server}/server-list/{server-list}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'vpn_ocvpn_forticlientaccess_authgroups': {
            'params': ['auth-groups', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/forticlient-access/auth-groups/{auth-groups}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn_overlays': {
            'params': ['device', 'overlays', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ocvpn_overlays_subnets': {
            'params': ['device', 'overlays', 'subnets', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ocvpn/overlays/{overlays}/subnets/{subnets}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_qkd': {
            'params': ['device', 'qkd', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/qkd/{qkd}'
            ],
            'mkey': 'id', 'v_range': [['7.4.3', '']]
        },
        'vpn_ssl_client': {
            'params': ['client', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/client/{client}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpn_ssl_settings_authenticationrule': {
            'params': ['authentication-rule', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/settings/authentication-rule/{authentication-rule}'
            ],
            'mkey': 'id', 'v_range': [['6.2.6', '6.2.13'], ['6.4.2', '']]
        },
        'vpnsslweb_userbookmark': {
            'params': ['device', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_userbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_userbookmark_bookmarks_formdata': {
            'params': ['bookmarks', 'device', 'form-data', 'user-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-bookmark/{user-bookmark}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark': {
            'params': ['device', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks': {
            'params': ['bookmarks', 'device', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'vpnsslweb_usergroupbookmark_bookmarks_formdata': {
            'params': ['bookmarks', 'device', 'form-data', 'user-group-bookmark', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/vpn/ssl/web/user-group-bookmark/{user-group-bookmark}/bookmarks/{bookmarks}/form-data/{form-data}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_cacheservice_dstpeer': {
            'params': ['device', 'dst-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service/dst-peer/{dst-peer}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_cacheservice_srcpeer': {
            'params': ['device', 'src-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/cache-service/src-peer/{src-peer}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule': {
            'params': ['content-delivery-network-rule', 'device'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules': {
            'params': ['content-delivery-network-rule', 'device', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_matchentries': {
            'params': ['content-delivery-network-rule', 'device', 'match-entries', 'rules'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/match-entries/{match-en'
                'tries}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wanopt_contentdeliverynetworkrule_rules_skipentries': {
            'params': ['content-delivery-network-rule', 'device', 'rules', 'skip-entries'],
            'urls': [
                '/pm/config/device/{device}/global/wanopt/content-delivery-network-rule/{content-delivery-network-rule}/rules/{rules}/skip-entries/{skip-entr'
                'ies}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_ftgdlocalrisk': {
            'params': ['device', 'ftgd-local-risk', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-local-risk/{ftgd-local-risk}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'webfilter_ftgdrisklevel': {
            'params': ['device', 'ftgd-risk-level', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/ftgd-risk-level/{ftgd-risk-level}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'webfilter_override': {
            'params': ['device', 'override', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/override/{override}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webfilter_searchengine': {
            'params': ['device', 'search-engine', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/webfilter/search-engine/{search-engine}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_debugurl': {
            'params': ['debug-url', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/debug-url/{debug-url}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_explicit_pacpolicy': {
            'params': ['device', 'pac-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/explicit/pac-policy/{pac-policy}'
            ],
            'mkey': 'policyid', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'webproxy_fastfallback': {
            'params': ['device', 'fast-fallback', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/fast-fallback/{fast-fallback}'
            ],
            'mkey': 'name', 'v_range': [['7.4.3', '']]
        },
        'webproxy_urlmatch': {
            'params': ['device', 'url-match', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/web-proxy/url-match/{url-match}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist': {
            'params': ['access-control-list', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv4rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv4-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv4-rules/{layer3-ipv4-rules}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_accesscontrollist_layer3ipv6rules': {
            'params': ['access-control-list', 'device', 'layer3-ipv6-rules', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/access-control-list/{access-control-list}/layer3-ipv6-rules/{layer3-ipv6-rules}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile': {
            'params': ['apcfg-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apcfgprofile_commandlist': {
            'params': ['apcfg-profile', 'command-list', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/apcfg-profile/{apcfg-profile}/command-list/{command-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_apstatus': {
            'params': ['ap-status', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ap-status/{ap-status}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_arrpprofile': {
            'params': ['arrp-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/arrp-profile/{arrp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bleprofile': {
            'params': ['ble-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ble-profile/{ble-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile': {
            'params': ['bonjour-profile', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_bonjourprofile_policylist': {
            'params': ['bonjour-profile', 'device', 'policy-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/bonjour-profile/{bonjour-profile}/policy-list/{policy-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqp3gppcellular': {
            'params': ['anqp-3gpp-cellular', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqp3gppcellular_mccmnclist': {
            'params': ['anqp-3gpp-cellular', 'device', 'mcc-mnc-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-3gpp-cellular/{anqp-3gpp-cellular}/mcc-mnc-list/{mcc-mnc-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpipaddresstype': {
            'params': ['anqp-ip-address-type', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-ip-address-type/{anqp-ip-address-type}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm': {
            'params': ['anqp-nai-realm', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist': {
            'params': ['anqp-nai-realm', 'device', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod': {
            'params': ['anqp-nai-realm', 'device', 'eap-method', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnairealm_nailist_eapmethod_authparam': {
            'params': ['anqp-nai-realm', 'auth-param', 'device', 'eap-method', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-nai-realm/{anqp-nai-realm}/nai-list/{nai-list}/eap-method/{eap-met'
                'hod}/auth-param/{auth-param}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpnetworkauthtype': {
            'params': ['anqp-network-auth-type', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-network-auth-type/{anqp-network-auth-type}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqproamingconsortium': {
            'params': ['anqp-roaming-consortium', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqproamingconsortium_oilist': {
            'params': ['anqp-roaming-consortium', 'device', 'oi-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-roaming-consortium/{anqp-roaming-consortium}/oi-list/{oi-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenuename': {
            'params': ['anqp-venue-name', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenuename_valuelist': {
            'params': ['anqp-venue-name', 'device', 'value-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-name/{anqp-venue-name}/value-list/{value-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenueurl': {
            'params': ['anqp-venue-url', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_anqpvenueurl_valuelist': {
            'params': ['anqp-venue-url', 'device', 'value-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/anqp-venue-url/{anqp-venue-url}/value-list/{value-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge': {
            'params': ['device', 'h2qp-advice-of-charge', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge_aoclist': {
            'params': ['aoc-list', 'device', 'h2qp-advice-of-charge', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpadviceofcharge_aoclist_planinfo': {
            'params': ['aoc-list', 'device', 'h2qp-advice-of-charge', 'plan-info', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-advice-of-charge/{h2qp-advice-of-charge}/aoc-list/{aoc-list}/plan-'
                'info/{plan-info}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpconncapability': {
            'params': ['device', 'h2qp-conn-capability', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-conn-capability/{h2qp-conn-capability}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpoperatorname': {
            'params': ['device', 'h2qp-operator-name', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpoperatorname_valuelist': {
            'params': ['device', 'h2qp-operator-name', 'value-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-operator-name/{h2qp-operator-name}/value-list/{value-list}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider': {
            'params': ['device', 'h2qp-osu-provider', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider_friendlyname': {
            'params': ['device', 'friendly-name', 'h2qp-osu-provider', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/friendly-name/{friendly-name}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovider_servicedescription': {
            'params': ['device', 'h2qp-osu-provider', 'service-description', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider/{h2qp-osu-provider}/service-description/{service-desc'
                'ription}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovidernai': {
            'params': ['device', 'h2qp-osu-provider-nai', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qposuprovidernai_nailist': {
            'params': ['device', 'h2qp-osu-provider-nai', 'nai-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-osu-provider-nai/{h2qp-osu-provider-nai}/nai-list/{nai-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qptermsandconditions': {
            'params': ['device', 'h2qp-terms-and-conditions', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-terms-and-conditions/{h2qp-terms-and-conditions}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_h2qpwanmetric': {
            'params': ['device', 'h2qp-wan-metric', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/h2qp-wan-metric/{h2qp-wan-metric}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_hsprofile': {
            'params': ['device', 'hs-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/hs-profile/{hs-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_icon': {
            'params': ['device', 'icon', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_icon_iconlist': {
            'params': ['device', 'icon', 'icon-list', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/icon/{icon}/icon-list/{icon-list}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap': {
            'params': ['device', 'qos-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap_dscpexcept': {
            'params': ['device', 'dscp-except', 'qos-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-except/{dscp-except}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_hotspot20_qosmap_dscprange': {
            'params': ['device', 'dscp-range', 'qos-map', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/hotspot20/qos-map/{qos-map}/dscp-range/{dscp-range}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_intercontroller_intercontrollerpeer': {
            'params': ['device', 'inter-controller-peer'],
            'urls': [
                '/pm/config/device/{device}/global/wireless-controller/inter-controller/inter-controller-peer/{inter-controller-peer}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile': {
            'params': ['device', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup': {
            'params': ['device', 'mpsk-group', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_mpskprofile_mpskgroup_mpskkey': {
            'params': ['device', 'mpsk-group', 'mpsk-key', 'mpsk-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/mpsk-profile/{mpsk-profile}/mpsk-group/{mpsk-group}/mpsk-key/{mpsk-key}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_nacprofile': {
            'params': ['device', 'nac-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/nac-profile/{nac-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_qosprofile': {
            'params': ['device', 'qos-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/qos-profile/{qos-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_region': {
            'params': ['device', 'region', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/region/{region}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_setting_offendingssid': {
            'params': ['device', 'offending-ssid', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/setting/offending-ssid/{offending-ssid}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp_community': {
            'params': ['community', 'device', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp_community_hosts': {
            'params': ['community', 'device', 'hosts', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/community/{community}/hosts/{hosts}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_snmp_user': {
            'params': ['device', 'user', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/snmp/user/{user}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_ssidpolicy': {
            'params': ['device', 'ssid-policy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/ssid-policy/{ssid-policy}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_syslogprofile': {
            'params': ['device', 'syslog-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/syslog-profile/{syslog-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_utmprofile': {
            'params': ['device', 'utm-profile', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/utm-profile/{utm-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap': {
            'params': ['device', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_macfilterlist': {
            'params': ['device', 'mac-filter-list', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mac-filter-list/{mac-filter-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_mpskkey': {
            'params': ['device', 'mpsk-key', 'vap', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/mpsk-key/{mpsk-key}'
            ],
            'mkey': None, 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_vlanname': {
            'params': ['device', 'vap', 'vdom', 'vlan-name'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-name/{vlan-name}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vap_vlanpool': {
            'params': ['device', 'vap', 'vdom', 'vlan-pool'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap/{vap}/vlan-pool/{vlan-pool}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_vapgroup': {
            'params': ['device', 'vap-group', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/vap-group/{vap-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wagprofile': {
            'params': ['device', 'vdom', 'wag-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wag-profile/{wag-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_widsprofile': {
            'params': ['device', 'vdom', 'wids-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wids-profile/{wids-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp': {
            'params': ['device', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtp_splittunnelingacl': {
            'params': ['device', 'split-tunneling-acl', 'vdom', 'wtp'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp/{wtp}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpgroup': {
            'params': ['device', 'vdom', 'wtp-group'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-group/{wtp-group}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile': {
            'params': ['device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}'
            ],
            'mkey': 'name', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_denymaclist': {
            'params': ['deny-mac-list', 'device', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/deny-mac-list/{deny-mac-list}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'wireless_wtpprofile_splittunnelingacl': {
            'params': ['device', 'split-tunneling-acl', 'vdom', 'wtp-profile'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/wireless-controller/wtp-profile/{wtp-profile}/split-tunneling-acl/{split-tunneling-acl}'
            ],
            'mkey': 'id', 'v_range': [['7.2.6', '7.2.9'], ['7.4.3', '']]
        },
        'ztna_reverseconnector': {
            'params': ['device', 'reverse-connector', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/reverse-connector/{reverse-connector}'
            ],
            'mkey': 'name', 'v_range': [['7.6.2', '']]
        },
        'ztna_trafficforwardproxy': {
            'params': ['device', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}'
            ],
            'mkey': 'name', 'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxy_sslciphersuites': {
            'params': ['device', 'ssl-cipher-suites', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxy_sslserverciphersuites': {
            'params': ['device', 'ssl-server-cipher-suites', 'traffic-forward-proxy', 'vdom'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/traffic-forward-proxy/{traffic-forward-proxy}/ssl-server-cipher-suites/{ssl-server-cipher-suites'
                '}'
            ],
            'mkey': None, 'v_range': [['7.6.0', '']]
        },
        'ztna_trafficforwardproxyreverseservice_remoteservers': {
            'params': ['device', 'remote-servers', 'vdom'],
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
            'params': ['bookmarks', 'device', 'vdom', 'web-portal-bookmark'],
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
            'params': ['api-gateway', 'device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6': {
            'params': ['api-gateway6', 'device', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6_realservers': {
            'params': ['api-gateway6', 'device', 'realservers', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway6_sslciphersuites': {
            'params': ['api-gateway6', 'device', 'ssl-cipher-suites', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway6/{api-gateway6}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway_realservers': {
            'params': ['api-gateway', 'device', 'realservers', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/realservers/{realservers}'
            ],
            'mkey': 'id', 'v_range': [['7.6.2', '']]
        },
        'ztna_webproxy_apigateway_sslciphersuites': {
            'params': ['api-gateway', 'device', 'ssl-cipher-suites', 'vdom', 'web-proxy'],
            'urls': [
                '/pm/config/device/{device}/vdom/{vdom}/ztna/web-proxy/{web-proxy}/api-gateway/{api-gateway}/ssl-cipher-suites/{ssl-cipher-suites}'
            ],
            'mkey': None, 'v_range': [['7.6.2', '']]
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
        'clone': {
            'required': True,
            'type': 'dict',
            'options': {
                'selector': {
                    'required': True,
                    'type': 'str',
                    'choices': list(clone_metadata.keys())
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
    fmgd = NAPIManager('clone', clone_metadata, None, None, None, module, connection)
    fmgd.process_task()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
