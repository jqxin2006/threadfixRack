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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

@Entity
@Table(name = "Application")
public class Application extends AuditableEntity {

	private static final long serialVersionUID = 1175222046579045669L;
	
	public static final String TEMP_PASSWORD = "this is not the password";
	private List<AccessControlApplicationMap> accessControlApplicationMaps;

	public static final int NAME_LENGTH = 60;
	public static final int URL_LENGTH = 255;
	
	@NotEmpty(message = "{errors.required}")
	@Size(max = NAME_LENGTH, message = "{errors.maxlength} " + NAME_LENGTH + ".")
	private String name;

	@URL(message = "{errors.url}")
	@Size(min = 0, max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
	private String url;
	
	@Size(min = 0, max = URL_LENGTH, message = "{errors.maxlength} " + URL_LENGTH + ".")
	private String uniqueId;
	
	@Size(max = 255, message = "{errors.maxlength} 255.")
	private String projectRoot;

	private Organization organization;
	private Waf waf;
	private ApplicationCriticality applicationCriticality;
	
	@Size(max = 50, message = "{errors.maxlength} 50.")
	private String projectName;
	
	@Size(max = 25, message = "{errors.maxlength} 25.")
	private String projectId;
	
	@Size(max = 50, message = "{errors.maxlength} 50.")
	private String component;
	private DefectTracker defectTracker;
	
	@Size(max = 80, message = "{errors.maxlength} 80.")
	private String userName;
	
	@Size(max = 80, message = "{errors.maxlength} 80.")
	private String password;

	@Size(max = 1024, message = "{errors.maxlength} 1024.")
	private String encryptedPassword;
	
	@Size(max = 1024, message = "{errors.maxlength} 1024.")
	private String encryptedUserName;
	
	private List<Defect> defectList;

	private List<ApplicationChannel> channelList;
	private List<Scan> scans;
	private List<Vulnerability> vulnerabilities;
	private List<RemoteProviderApplication> remoteProviderApplications;

	// these are here so we don't generate them more than we need to
	private List<Integer> reportList = null;
	private List<Finding> findingList = null;
	private List<ApplicationChannel> uploadableChannels = null;

	@Column(length = NAME_LENGTH, nullable = false)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = 255)
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}
	
	@Column(length = 255)
	public String getUniqueId() {
		return uniqueId;
	}

	public void setUniqueId(String uniqueId) {
		this.uniqueId = uniqueId;
	}

	@Column(length = 50)
	public String getProjectName() {
		return projectName;
	}

	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}

	@Column(length = 25)
	public String getProjectId() {
		return projectId;
	}

	public void setProjectId(String projectId) {
		this.projectId = projectId;
	}

	@Column(length = 50, nullable = true)
	public String getComponent() {
		return component;
	}

	public void setComponent(String component) {
		this.component = component;
	}
	
	@Transient
	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	@Transient
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	@Column(length = 1024)
	@JsonIgnore
	public String getEncryptedPassword() {
		return encryptedPassword;
	}

	public void setEncryptedPassword(String encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
	}

	@Column(length = 1024)
	@JsonIgnore
	public String getEncryptedUserName() {
		return encryptedUserName;
	}

	public void setEncryptedUserName(String encryptedUserName) {
		this.encryptedUserName = encryptedUserName;
	}

	@ManyToOne(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
	@JoinColumn(name = "defectTrackerId")
	public DefectTracker getDefectTracker() {
		return defectTracker;
	}

	public void setDefectTracker(DefectTracker defectTracker) {
		this.defectTracker = defectTracker;
	}

	@OneToMany(mappedBy = "application")
	public List<Defect> getDefectList() {
		return defectList;
	}

	public void setDefectList(List<Defect> defectList) {
		this.defectList = defectList;
	}

	@ManyToOne
	@JoinColumn(name = "organizationId")
	@JsonIgnore
	public Organization getOrganization() {
		return organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}

	@ManyToOne(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
	@JoinColumn(name = "wafId")
	public Waf getWaf() {
		return waf;
	}

	public void setWaf(Waf waf) {
		this.waf = waf;
	}

	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
	public List<ApplicationChannel> getChannelList() {
		return channelList;
	}

	public void setChannelList(List<ApplicationChannel> channelList) {
		this.channelList = channelList;
	}

	@OneToMany(mappedBy = "application")
	@OrderBy("importTime DESC")
	@JsonIgnore
	public List<Scan> getScans() {
		return scans;
	}

	public void setScans(List<Scan> scans) {
		this.scans = scans;
	}
	
	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<AccessControlApplicationMap> getAccessControlApplicationMaps() {
		return accessControlApplicationMaps;
	}

	public void setAccessControlApplicationMaps(List<AccessControlApplicationMap> accessControlApplicationMaps) {
		this.accessControlApplicationMaps = accessControlApplicationMaps;
	}

	@OneToMany(mappedBy = "application", cascade = CascadeType.ALL)
	@OrderBy("genericSeverity, genericVulnerability")
	public List<Vulnerability> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}
	
	@Column(length = 256)
	public String getProjectRoot() {
		return projectRoot;
	}
	
	public void setProjectRoot(String projectRoot) {
		this.projectRoot = projectRoot;
	}
	
	@OneToMany(mappedBy = "application")
	public List<RemoteProviderApplication> getRemoteProviderApplications() {
		return remoteProviderApplications;
	}

	public void setRemoteProviderApplications(
			List<RemoteProviderApplication> remoteProviderApplications) {
		this.remoteProviderApplications = remoteProviderApplications;
	}
	
	@ManyToOne
	@JoinColumn(name = "applicationCriticalityId")
	public ApplicationCriticality getApplicationCriticality() {
		return applicationCriticality;
	}

	public void setApplicationCriticality(ApplicationCriticality applicationCriticality) {
		this.applicationCriticality = applicationCriticality;
	}
	
	/*
	 * Index Severity 0 Info 1 Low 2 Medium 3 High 4 Critical 5 # Total vulns
	 */
	@Transient
	@JsonIgnore
	public List<Integer> getVulnerabilityReport() {
		return reportList;
	}
	
	public void setVulnerabilityReport(List<Integer> vulnReport) {
		this.reportList = vulnReport;
	}

	@Transient
	@JsonIgnore
	public List<Finding> getFindingList() {
		if (findingList != null)
			return findingList;
		List<Finding> findings = new ArrayList<Finding>();
		for (Vulnerability vuln : getVulnerabilities()) {
			for (Finding finding : vuln.getFindings()) {
				if (finding != null) {
					findings.add(finding);
				}
			}
		}
		findingList = findings;
		return findings;
	}
	
	@Transient
	@JsonIgnore
	public List<Vulnerability> getActiveVulnerabilities() {
		List<Vulnerability> result = new ArrayList<Vulnerability>();
		for(Vulnerability vuln : vulnerabilities) {
			if(vuln.isActive() && !vuln.getIsFalsePositive()){
				result.add(vuln);
			}
		}
		return result;
	}
	
	@Transient
	@JsonIgnore
	public List<Vulnerability> getClosedVulnerabilities() {
		List<Vulnerability> result = new ArrayList<Vulnerability>();
		for(Vulnerability vuln : vulnerabilities) {
			if(!vuln.isActive()){
				result.add(vuln);
			}
		}
		return result;
	}
	
	@Transient
	@JsonIgnore
	public List<ApplicationChannel> getUploadableChannels() {
		
		if (uploadableChannels != null)
			return uploadableChannels;
		
		List<ApplicationChannel> normalList = getChannelList();
		if (normalList == null || normalList.size() == 0)
			return new ArrayList<ApplicationChannel>();
		
		Set<String> doNotIncludeSet = new HashSet<String>();
		doNotIncludeSet.add(ChannelType.MANUAL);
		doNotIncludeSet.add(ChannelType.SENTINEL);
		doNotIncludeSet.add(ChannelType.VERACODE);
		doNotIncludeSet.add(ChannelType.QUALYSGUARD_WAS);
		
		List<ApplicationChannel> returnList = new ArrayList<ApplicationChannel>();
	
		for (ApplicationChannel channel : normalList) {
			if (channel != null && channel.getChannelType() != null 
					&& channel.getChannelType().getName() != null
					&& !doNotIncludeSet.contains(channel.getChannelType().getName())) {
				returnList.add(channel);
			}
		}
		uploadableChannels = returnList;
		return returnList;
	}

}
