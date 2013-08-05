////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.entities;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name = "ChannelType")
public class ChannelType extends BaseEntity {

	private static final long serialVersionUID = 1665587716223810215L;
	
	// Types of channels
	public static final String ACUNETIX_WVS = "Acunetix WVS";
	public static final String APPSCAN_DYNAMIC = "IBM Rational AppScan";
	public static final String ARACHNI = "Arachni";
	public static final String BRAKEMAN = "Brakeman";
	public static final String BURPSUITE = "Burp Suite";
	public static final String CAT_NET = "Microsoft CAT.NET";
	public static final String FINDBUGS = "FindBugs";
	public static final String FORTIFY = "Fortify 360";
	public static final String MANUAL = "Manual";
	public static final String NESSUS = "Nessus";
	public static final String NTO_SPIDER = "NTO Spider";
	public static final String NETSPARKER = "Mavituna Security Netsparker";
	public static final String QUALYSGUARD_WAS = "QualysGuard WAS";
	public static final String SENTINEL = "WhiteHat Sentinel";
	public static final String SKIPFISH = "Skipfish";
	public static final String VERACODE = "Veracode";
	public static final String W3AF = "w3af";
	public static final String WEBINSPECT = "WebInspect";
	public static final String ZAPROXY = "OWASP Zed Attack Proxy";
	public static final String APPSCAN_SOURCE = "IBM Rational AppScan Source Edition";
	public static final String APPSCAN_ENTERPRISE = "IBM Rational AppScan Enterprise";
	
	// This set is used to hold the channel types that should include their native IDs in the vuln description.
	// Any useful native IDs should be included here, but not ones that we generate ourselves.
	public final static Set<String> NATIVE_ID_SCANNERS = new HashSet<>(Arrays.asList(
			CAT_NET,
			FORTIFY, 
			SENTINEL,
			VERACODE));

	private List<ApplicationChannel> applicationChannels;
	private List<ChannelSeverity> channelSeverities;
	private List<ChannelVulnerability> channelVulnerabilities;
	private List<RemoteProviderType> remoteProviderTypes;
	
	private String name;
	private String url;
	private String version;
	private String exportInfo;

	@Column(length = 50, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = 20, nullable = false)
	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	@Column(length = 255, nullable = true)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	@Column(length = 1024, nullable = true)
	public String getExportInfo() {
		return exportInfo;
	}

	public void setExportInfo(String exportInfo) {
		this.exportInfo = exportInfo;
	}

	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<ChannelVulnerability> getChannelVulnerabilities() {
		return channelVulnerabilities;
	}

	public void setChannelVulnerabilities(List<ChannelVulnerability> channelVulnerabilities) {
		this.channelVulnerabilities = channelVulnerabilities;
	}

	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<ChannelSeverity> getChannelSeverities() {
		return channelSeverities;
	}

	public void setChannelSeverities(List<ChannelSeverity> channelSeverities) {
		this.channelSeverities = channelSeverities;
	}

	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<ApplicationChannel> getChannels() {
		return applicationChannels;
	}

	public void setChannels(List<ApplicationChannel> applicationChannels) {
		this.applicationChannels = applicationChannels;
	}
	
	@OneToMany(mappedBy = "channelType")
	@JsonIgnore
	public List<RemoteProviderType> getRemoteProviderTypes() {
		return remoteProviderTypes;
	}

	public void setRemoteProviderTypes(List<RemoteProviderType> remoteProviderTypes) {
		this.remoteProviderTypes = remoteProviderTypes;
	}

}
