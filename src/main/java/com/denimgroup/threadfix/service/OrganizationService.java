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
package com.denimgroup.threadfix.service;

import java.util.List;

import com.denimgroup.threadfix.data.entities.Organization;

/**
 * @author bbeverly
 * 
 */
public interface OrganizationService {

	/**
	 * @return
	 */
	List<Organization> loadAllActive();

	/**
	 * @return
	 */
	List<Organization> loadAllNoOrder();

	/**
	 * @param organizationId
	 * @return
	 */
	Organization loadOrganization(int organizationId);

	/**
	 * @param name
	 * @return
	 */
	Organization loadOrganization(String name);

	/**
	 * @param organization
	 */
	void storeOrganization(Organization organization);

	/**
	 * Prepare the Organization for deletion.
	 * 
	 * @param organizationId
	 */
	void deactivateOrganization(Organization organization);
	
	/**
	 * This method is meant to be used with REST methods 
	 * to take the validation out of the Controller layer.
	 * @param organization
	 * @return boolean
	 */
	boolean isValidOrganization(Organization organization);
	
	/**
	 * this method filters loadAllActive with access groups in mind.
	 * @return
	 */
	List<Organization> loadAllActiveFilter();

}
