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
package com.denimgroup.threadfix.data.dao;

import java.util.List;
import java.util.Set;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * Basic DAO class for the Application entity.
 * 
 * @author bbeverly
 */
public interface ApplicationDao {

	/**
	 * @return
	 */
	List<Application> retrieveAll();

	/**
	 * @return
	 */
	List<Application> retrieveAllActive();
	
	/**
	 * 
	 * @param authenticatedTeamIds
	 * @return
	 */
	List<Application> retrieveAllActiveFilter(Set<Integer> authenticatedTeamIds);

	/**
	 * @param id
	 * @return
	 */
	Application retrieveById(int id);

	/**
	 * @param name
	 * @return
	 */
	Application retrieveByName(String name);

	/**
	 * @param application
	 */
	void saveOrUpdate(Application application);

	/**
	 * 
	 * @param application
	 * @return
	 */
	List<Integer> loadVulnerabilityReport(Application application);
	
	/**
	 * 
	 * @param appIds
	 * @return
	 */
	List<String> getTeamNames(List<Integer> appIds);
	
	/**
	 * 
	 * @param app
	 */
	List<Vulnerability> getVulns(Application app);
	
	/**
	 */
	List<Integer> getTopXVulnerableAppsFromList(int numApps, List<Integer> applicationIdList);

}
