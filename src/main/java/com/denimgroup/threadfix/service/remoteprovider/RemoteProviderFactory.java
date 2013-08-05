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
package com.denimgroup.threadfix.service.remoteprovider;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;

public class RemoteProviderFactory {
	
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ChannelTypeDao channelTypeDao = null;
	
	@Autowired
	public RemoteProviderFactory(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, 
			ChannelSeverityDao channelSeverityDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
	}

	public List<RemoteProviderApplication> fetchApplications(RemoteProviderType remoteProviderType) {
		RemoteProvider provider = getProvider(remoteProviderType.getName());
		
		if (provider == null)
			return null;
		
		provider.setRemoteProviderType(remoteProviderType);
		return provider.fetchApplications();
	}
	
	public RemoteProvider getProvider(String providerType) {
		if (providerType == null) {
			return null;
		} else if (providerType.equals(RemoteProviderType.SENTINEL)) {
			return new WhiteHatRemoteProvider(channelTypeDao, channelVulnerabilityDao, 
					channelSeverityDao);
		} else if (providerType.equals(RemoteProviderType.VERACODE)) {
			return new VeracodeRemoteProvider(channelTypeDao, channelVulnerabilityDao, 
					channelSeverityDao);
		} else if (providerType.equals(RemoteProviderType.QUALYSGUARD_WAS)) {
			return new QualysRemoteProvider(channelTypeDao, channelVulnerabilityDao, 
					channelSeverityDao);
		} else {
			return null;
		}
	}

	/**
	 * This method takes a remoteProviderApplication and does the rest of the work of getting
	 * a scan file from the remote provider in question.
	 * @param remoteProviderApplication
	 * @return
	 */
	public List<Scan> fetchScans(RemoteProviderApplication remoteProviderApplication) {
		if (remoteProviderApplication == null || 
				remoteProviderApplication.getRemoteProviderType() == null) {
			return null;
		}
		
		RemoteProvider provider = getProvider(remoteProviderApplication.getRemoteProviderType().getName());
		
		if (provider == null)
			return null;
		
		List<Scan> scanList = provider.getScans(remoteProviderApplication);
		
		if (remoteProviderApplication.getApplicationChannel() != null) { 
			if (remoteProviderApplication.getApplicationChannel().getScanCounter() == null) {
				remoteProviderApplication.getApplicationChannel().setScanCounter(1);
			} else {
				remoteProviderApplication.getApplicationChannel().setScanCounter(
						remoteProviderApplication.getApplicationChannel().getScanCounter() + 1);
			}
		}
		
		return scanList;
	}
	
}
