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

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/wafs/new")
@SessionAttributes("waf")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
public class AddWafController {
	
	public AddWafController(){}

	private WafService wafService = null;
	private ApplicationService applicationService = null;
	private PermissionService permissionService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(AddWafController.class);

	@Autowired
	public AddWafController(ApplicationService applicationService, 
			WafService wafService, PermissionService permissionService) {
		this.wafService = wafService;
		this.applicationService = applicationService;
		this.permissionService = permissionService;
	}

	@ModelAttribute
	public List<WafType> populateWafTypes() {
		return wafService.loadAllWafTypes();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String newForm(Model model) {
		Waf waf = new Waf();
		model.addAttribute(waf);
		return "wafs/form";
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String [] { "name", "wafType.id", "applicationId" });
	}

	@RequestMapping(value="/ajax/appPage", method = RequestMethod.POST)
	public String newSubmitAjaxAppPage(@Valid @ModelAttribute Waf waf, 
			BindingResult result,
			SessionStatus status, Model model,
			HttpServletRequest request) {
		model.addAttribute("createWafUrl", "/wafs/new/ajax/appPage");
		
		String validationResult = newSubmit(waf,result,status,model,request);
		
		if (validationResult != "SUCCESS") {
			return validationResult;
		}
		
		Application application = null;
		if (request.getParameter("applicationId") != null) {
			Integer testId = null;
			try {
				testId = Integer.valueOf((String)request.getParameter("applicationId"));
				application = applicationService.loadApplication(testId);
			} catch (NumberFormatException e) {
				log.warn("Non-numeric value discovered in applicationId field. Someone is trying to tamper with it.");
			}
		}
		
		if (application != null) {
			application.setWaf(waf);
			applicationService.storeApplication(application);
		}
		model.addAttribute(application);
		model.addAttribute("addedWaf", true);
		model.addAttribute("contentPage", "applications/wafRow.jsp");
		
		return "ajaxSuccessHarness";
	}
	
	@RequestMapping(value="/ajax", method = RequestMethod.POST)
	public String newSubmitAjax(@Valid @ModelAttribute Waf waf, 
			BindingResult result,
			SessionStatus status, Model model,
			HttpServletRequest request) {
		model.addAttribute("createWafUrl", "/wafs/new/ajax");

		String validationResult = newSubmit(waf,result,status,model,request);
		
		if (validationResult != "SUCCESS") {
			return validationResult;
		}
		
		model.addAttribute("successMessage", "WAF " + waf.getName() + " was successfully created.");
		model.addAttribute("contentPage", "wafs/wafsTable.jsp");
		
		return "ajaxSuccessHarness";
	}
	
	public String newSubmit(@Valid @ModelAttribute Waf waf, 
			BindingResult result,
			SessionStatus status, Model model,
			HttpServletRequest request) {
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "wafs/forms/createWafForm.jsp");
			return "ajaxFailureHarness";
		} else {
			if (waf.getName().trim().equals("")) {
				result.rejectValue("name", null, null, "This field cannot be blank");
			} else {
				Waf databaseWaf = wafService.loadWaf(waf.getName().trim());
				if (databaseWaf != null) {
					result.rejectValue("name", "errors.nameTaken");
				}
			}
			
			if (waf.getWafType() == null)
				result.rejectValue("wafType.id", "errors.required", new String [] { "WAF Type" }, null );
			else if (wafService.loadWafType(waf.getWafType().getId()) == null)
				result.rejectValue("wafType.id", "errors.invalid", new String [] { waf.getWafType().getId().toString() }, null );
			else 
				waf.setWafType(wafService.loadWafType(waf.getWafType().getId()));
			
			if (result.hasErrors()) {
				model.addAttribute("contentPage", "wafs/forms/createWafForm.jsp");
				return "ajaxFailureHarness";
			}
			
			wafService.storeWaf(waf);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(currentUser + " has created a WAF with the name " + waf.getName() + 
					", the type " + waf.getWafType().getName() + 
					" and ID " + waf.getId() + ".");
			
			model.addAttribute(wafService.loadAll());
			model.addAttribute("newWaf", new Waf());
			model.addAttribute("waf", new Waf());
			model.addAttribute("wafPage", true);
			permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_WAFS);
			
			return "SUCCESS";
		}
	}
}
