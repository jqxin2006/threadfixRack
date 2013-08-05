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
package com.denimgroup.threadfix.webapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.SurveyResult;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.SurveyService;

@Controller
@RequestMapping("/organizations/{orgId}/surveys/{resultId}")
public class SurveysController {

	private final SurveyService surveyService;
	private final PermissionService permissionService;

	private final SanitizedLogger log = new SanitizedLogger(SurveysController.class);
	
	@Autowired
	public SurveysController(SurveyService surveyService,
			PermissionService permissionService) {
		this.surveyService = surveyService;
		this.permissionService = permissionService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String detail(@PathVariable("orgId") int orgId, 
			@PathVariable("resultId") int resultId, Model model) {
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, null)){
			return "403";
		}
		
		SurveyResult surveyResult = surveyService.loadSurveyResult(resultId);
		
		if (surveyResult == null) {
			log.warn(ResourceNotFoundException.getLogMessage("SurveyResult", resultId));
			throw new ResourceNotFoundException();
		}

		model.addAttribute(surveyResult);
		return "surveys/detail";
	}
}
