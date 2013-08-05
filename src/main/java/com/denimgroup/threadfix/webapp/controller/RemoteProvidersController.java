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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.RemoteProviderApplicationService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService.ResponseCode;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("configuration/remoteproviders")
@SessionAttributes(value= {"remoteProviderType", "remoteProviderApplication"})
public class RemoteProvidersController {
	
	public RemoteProvidersController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(RemoteProvidersController.class);
	
	private RemoteProviderTypeService remoteProviderTypeService;
	private PermissionService permissionService;
	private RemoteProviderApplicationService remoteProviderApplicationService;
	private OrganizationService organizationService;
	
	@Autowired
	public RemoteProvidersController(RemoteProviderTypeService remoteProviderTypeService,
			RemoteProviderApplicationService remoteProviderApplicationService,
			PermissionService permissionService, OrganizationService organizationService) {
		this.remoteProviderTypeService = remoteProviderTypeService;
		this.remoteProviderApplicationService = remoteProviderApplicationService;
		this.organizationService = organizationService;
		this.permissionService = permissionService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "apiKey", "username", 
				"password", "application.id", "application.organization.id", "isEuropean" });
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		log.info("Processing request for Remote Provider index.");
		List<RemoteProviderType> typeList = remoteProviderTypeService.loadAll();
		
		for (RemoteProviderType type : typeList) {
			if (type != null && type.getApiKey() != null) {
				type.setApiKey(mask(type.getApiKey()));
			}
		}

		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));
		permissionService.filterApps(typeList);
		
		model.addAttribute("remoteProviders", typeList);
		model.addAttribute("remoteProviderType", new RemoteProviderType());
		model.addAttribute("remoteProviderApplication", new RemoteProviderApplication());
		model.addAttribute("organizationList", organizationService.loadAllActiveFilter());
		
		permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_REMOTE_PROVIDERS);
		return "config/remoteproviders/index";
	}
	
	private String mask(String input) {
		if (input != null) {
			if (input.length() > 5) {
				String replaced = input.replace(input.substring(0,input.length() - 4), 
						RemoteProviderTypeService.API_KEY_PREFIX);
				return replaced;
			} else {
				// should never get here, but let's not return the info anyway
				return RemoteProviderTypeService.API_KEY_PREFIX;
			}
		} else {
			return null;
		}
	}
	
	@RequestMapping(value="/{typeId}/update", method = RequestMethod.GET)
	public String updateApps(@PathVariable("typeId") int typeId, HttpServletRequest request) {
		log.info("Processing request for RemoteProviderType update.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		remoteProviderApplicationService.updateApplications(remoteProviderType);
		remoteProviderTypeService.store(remoteProviderType);
		
		ControllerUtils.addSuccessMessage(request, "ThreadFix updated applications from " + 
				remoteProviderType + ".");
		
		return "redirect:/configuration/remoteproviders/";
	}
	
	@RequestMapping(value="/{typeId}/importAll", method = RequestMethod.GET)
	public String importAllScans(@PathVariable("typeId") int typeId, HttpServletRequest request) {
		log.info("Processing request for RemoteProviderType bulk import.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		
		remoteProviderApplicationService.addBulkImportToQueue(remoteProviderType);
		
		ControllerUtils.addSuccessMessage(request, "ThreadFix is importing scans from " + remoteProviderType + 
			" in the background. It may take a few minutes to finish the process.");
		
		return "redirect:/configuration/remoteproviders/";
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/import", method = RequestMethod.GET)
	public String importScan(@PathVariable("typeId") int typeId, 
			HttpServletRequest request, @PathVariable("appId") int appId) {
		
		log.info("Processing request for scan import.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		if (remoteProviderApplication == null || remoteProviderApplication.getApplication() == null) {
			request.getSession().setAttribute("errorMessage", 
					"The scan request failed because it could not find the requested application.");

			return "redirect:/configuration/remoteproviders/";
		}
		
		if (remoteProviderApplication.getApplication().getId() == null ||
				remoteProviderApplication.getApplication().getOrganization() == null ||
				remoteProviderApplication.getApplication().getOrganization().getId() == null ||
				!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, 
						remoteProviderApplication.getApplication().getOrganization().getId(), 
						remoteProviderApplication.getApplication().getId())) {
			return "403";
		}
		
		remoteProviderTypeService.decryptCredentials(
				remoteProviderApplication.getRemoteProviderType());
		
		if (remoteProviderApplicationService.importScansForApplication(remoteProviderApplication)) {
			return "redirect:/organizations/" + 
						remoteProviderApplication.getApplication().getOrganization().getId() + 
						"/applications/" +
						remoteProviderApplication.getApplication().getId();
		} else {
			request.getSession().setAttribute("errorMessage", "No new scans were found.");
			return "redirect:/configuration/remoteproviders/";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{appId}/edit", method = RequestMethod.POST)
	public String configureAppSubmit(@PathVariable("typeId") int typeId, @PathVariable("appId") int appId,
			@Valid @ModelAttribute RemoteProviderApplication remoteProviderApplication, 
			BindingResult result, SessionStatus status,
			Model model, HttpServletRequest request) {
		if (result.hasErrors() || remoteProviderApplication.getApplication() == null) {
			return "config/remoteproviders/edit";
		} else {
//			permissionService.isAuthorized(Permission.CAN_MANAGE_REMOTE_PROVIDERS, null, null);
			
			RemoteProviderApplication dbRemoteProviderApplication = 
					remoteProviderApplicationService.load(appId);
			
			dbRemoteProviderApplication.setApplication(remoteProviderApplication.getApplication());
			
			remoteProviderApplicationService.processApp(result, dbRemoteProviderApplication);
			
			if (result.hasErrors()) {
				String error = "Invalid submission.";
				model.addAttribute("errorMessage", error);
				model.addAttribute("remoteProviderApplication",remoteProviderApplication);
				model.addAttribute("contentPage", "config/remoteproviders/editMapping.jsp");
				model.addAttribute("organizationList", organizationService.loadAllActiveFilter());
				return "ajaxFailureHarness";
			}

			ControllerUtils.addSuccessMessage(request, "Application successfully updated.");
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		}
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.POST)
	public String configureFinish(@PathVariable("typeId") int typeId,
			HttpServletRequest request, Model model) {
		
		ResponseCode test = remoteProviderTypeService.checkConfiguration(
				request.getParameter("username"),
				request.getParameter("password"), 
				request.getParameter("apiKey"), typeId);
		
		if (test.equals(ResponseCode.BAD_ID)) {
			return "403";
		} else if (test.equals(ResponseCode.NO_APPS)) {
			
			String error = "We were unable to retrieve a list of applications using these credentials." +
					" Please ensure that the credentials are valid and that there are applications " +
					"available in the account.";
			model.addAttribute("errorMessage", error);
			model.addAttribute("remoteProviderType", remoteProviderTypeService.load(typeId));
			model.addAttribute("contentPage", "config/remoteproviders/configure.jsp");
			return "ajaxFailureHarness";
		} else if (test.equals(ResponseCode.SUCCESS)) {
			ControllerUtils.addSuccessMessage(request, "Applications successfully updated.");
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		} else {
			ControllerUtils.addErrorMessage(request, "An unidentified error occurred.");
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/clearConfiguration", method = RequestMethod.POST)
	public String clearConfiguration(@PathVariable("typeId") int typeId,
			HttpServletRequest request) {
		
		RemoteProviderType type = remoteProviderTypeService.load(typeId);
		
		if (type != null) {
			remoteProviderTypeService.clearConfiguration(typeId);
			ControllerUtils.addSuccessMessage(request, type.getName() + " configuration was cleared successfully.");
		}

		return "redirect:/configuration/remoteproviders";
	}
}
