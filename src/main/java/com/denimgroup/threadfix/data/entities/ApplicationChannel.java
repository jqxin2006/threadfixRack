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

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name = "ApplicationChannel")
public class ApplicationChannel extends AuditableEntity {

	private static final long serialVersionUID = 184587892482641379L;

	private Application application;
	private ChannelType channelType;

	private List<Scan> scanList;
	
	private List<JobStatus> jobStatusList;
	
	private Integer scanCounter;

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonIgnore
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	@ManyToOne
	@JoinColumn(name = "channelTypeId")
	public ChannelType getChannelType() {
		return channelType;
	}

	public void setChannelType(ChannelType channelType) {
		this.channelType = channelType;
	}
	
	@Column
	public Integer getScanCounter() {
		return scanCounter;
	}

	public void setScanCounter(Integer scanCounter) {
		this.scanCounter = scanCounter;
	}

	@OneToMany(mappedBy = "applicationChannel")
	@JsonIgnore
	public List<Scan> getScanList() {
		return scanList;
	}

	public void setScanList(List<Scan> scanList) {
		this.scanList = scanList;
	}

	@OneToMany(mappedBy = "applicationChannel")
	@JsonIgnore
	public List<JobStatus> getJobStatusList() {
		return jobStatusList;
	}

	public void setJobStatusList(List<JobStatus> jobStatusList) {
		this.jobStatusList = jobStatusList;
	}
}
