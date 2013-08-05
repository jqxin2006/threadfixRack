package com.denimgroup.threadfix.webapp.controller;

import java.net.MalformedURLException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.ScanTypeCalculationService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.service.channel.ScanImportStatus;

@Controller
@RequestMapping("/rest/teams/{teamId}/applications")
public class ApplicationRestController extends RestController {
	
	public static final String CREATION_FAILED = "New Application creation failed.";
	public static final String LOOKUP_FAILED = "Application lookup failed.";
	public static final String ADD_CHANNEL_FAILED = "Adding an Application Channel failed.";
	public static final String SET_WAF_FAILED = "Call to setWaf failed.";
	public static final String CHANNEL_LOOKUP_FAILED = "Application Channel lookup failed.";
	
	private OrganizationService organizationService;
	private ApplicationService applicationService;
	private ScanService scanService;
	private ScanTypeCalculationService scanTypeCalculationService;
	private ScanMergeService scanMergeService;
	private WafService wafService;
	private ApplicationCriticalityService applicationCriticalityService;
	
	private final static String DETAIL = "applicationDetail", 
		LOOKUP = "applicationLookup",
		NEW = "newApplication",
		SET_WAF = "setWaf",
		UPLOAD = "uploadScan";

	// TODO finalize which methods need to be restricted
	static {
		restrictedMethods.add(NEW);
		restrictedMethods.add(SET_WAF);
	}
	
	@Autowired
	public ApplicationRestController(OrganizationService organizationService,
			APIKeyService apiKeyService, ApplicationService applicationService,
			ScanService scanService, ScanMergeService scanMergeService,
			ScanTypeCalculationService scanTypeCalculationService, 
			WafService wafService,
			ApplicationCriticalityService applicationCriticalityService) {
		this.organizationService = organizationService;
		this.apiKeyService = apiKeyService;
		this.applicationService = applicationService;
		this.scanTypeCalculationService = scanTypeCalculationService;
		this.scanService = scanService;
		this.scanMergeService = scanMergeService;
		this.wafService = wafService;
		this.applicationCriticalityService = applicationCriticalityService;
	}
	
	/**
	 * Create a new application with the supplied name and URL. 
	 * The rest of the configuration is done through other methods.
	 * @param request
	 * @param teamId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/new", method=RequestMethod.POST)
	public @ResponseBody Object newApplication(HttpServletRequest request,
			@PathVariable("teamId") int teamId) {
		log.info("Received REST request for a new Application.");

		String result = checkKey(request, NEW);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		// By not using @RequestParam notations, we can catch the error in the code
		// and provide better error messages.
		String name = request.getParameter("name");
		String url = request.getParameter("url");
		
		if (name == null || url == null) {
			log.warn("Call to New Application was missing either the name or URL parameter.");
			return CREATION_FAILED;
		}
		
		// test URL format
		try {
			new URL(url);
		} catch (MalformedURLException e) {
			log.warn("The supplied URL was not formatted correctly.");
			return CREATION_FAILED;
		}
		
		Organization organization = organizationService.loadOrganization(teamId);
		
		if (organization == null) {
			log.warn("Invalid Team ID.");
			return CREATION_FAILED;
		}
		
		Application application = new Application();
		if (name != null && url != null) {
			application.setOrganization(organization);
			application.setName(name.trim());
			application.setUrl(url.trim());
			// TODO include this as a parameter
			application.setApplicationCriticality(
					applicationCriticalityService.loadApplicationCriticality(
							ApplicationCriticality.LOW));
		}
		
		if (applicationService.checkApplication(application)) {
			applicationService.storeApplication(application);
			return application;
		} else {
			return CREATION_FAILED;
		}
	}
	
	/**
	 * Return details about a specific application.
	 * @param request
	 * @param appId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}", method=RequestMethod.GET)
	public @ResponseBody Object applicationDetail(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		log.info("Received REST request for Applications with teamId = " + appId + ".");

		String result = checkKey(request, DETAIL);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(LOOKUP_FAILED);
			return LOOKUP_FAILED;
		}
		return application;
	}
	
	/**
	 * Return details about a specific application.
	 * @param request
	 * @param appName
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/lookup", method=RequestMethod.GET)
	public @ResponseBody Object applicationLookup(HttpServletRequest request) {
		
		String appName = request.getParameter("name");

		String result = checkKey(request, LOOKUP);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		if (appName == null) {
			return LOOKUP_FAILED;
		}
		
		log.info("Received REST request for Applications with teamId = " + appName + ".");
		
		Application application = applicationService.loadApplication(appName);
		
		if (application == null) {
			log.warn(LOOKUP_FAILED);
			return LOOKUP_FAILED;
		}
		return application;
	}
	
	/**
	 * Allows the user to upload a scan to an existing application channel.
	 * @param appId
	 * @param request
	 * @param applicationId
	 * @param file
	 * @return Status response. We may change this to make it more useful.
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/upload", method=RequestMethod.POST)
	public @ResponseBody Object uploadScan(@PathVariable("appId") int appId, 
			@PathVariable("teamId") int teamId, HttpServletRequest request,
			@RequestParam("file") MultipartFile file) {
		log.info("Received REST request to upload a scan to application " + appId + ".");

		String result = checkKey(request, UPLOAD);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));
		
		String fileName = scanTypeCalculationService.saveFile(myChannelId, file);
		
		ScanCheckResultBean returnValue = scanService.checkFile(myChannelId, fileName);
		
		if (ScanImportStatus.SUCCESSFUL_SCAN == returnValue.getScanCheckResult()) {
			Scan scan = scanMergeService.saveRemoteScanAndRun(myChannelId, fileName);
			return scan;
		} else if (ScanImportStatus.EMPTY_SCAN_ERROR == returnValue.getScanCheckResult()) {
			return "You attempted to upload an empty scan.";
		} else {
			return "The scan upload attempt returned this message: " + returnValue.getScanCheckResult();
		}
	}
	
	/**
	 * Overwrites the WAF for the application.
	 * @param request
	 * @param appId
	 * @param wafId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/setWaf", method=RequestMethod.POST)
	public @ResponseBody Object setWaf(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		
		String idString = request.getParameter("wafId");
		
		Integer wafId = null;
		
		if (idString != null) {
			try {
				wafId = Integer.valueOf(idString);
			} catch (NumberFormatException e) {
				log.warn("Non-integer parameter was submitted to setWaf.");
			}
			if (wafId != null) {
				log.info("Received REST request to add WAF " + wafId + " to Application " + appId + ".");
			}
		}
		
		if (wafId == null) {
			log.warn("Received incomplete REST request to add a WAF");
			return SET_WAF_FAILED;
		}

		String result = checkKey(request, SET_WAF);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		Waf waf = wafService.loadWaf(wafId);
		
		if (application == null) {
			log.warn("Invalid Application ID.");
			return SET_WAF_FAILED;
		} else if (waf == null) {
			log.warn("Invalid WAF ID");
			return SET_WAF_FAILED;
		} else {
			
			// Delete WAF rules if the WAF has changed
			Integer oldWafId = null;
			
			if (application.getWaf() != null && application.getWaf().getId() != null) {
				oldWafId = application.getWaf().getId();
			}
			
			application.setWaf(waf);
			applicationService.updateWafRules(application, oldWafId);
			applicationService.storeApplication(application);
			return application;
		}
	}
}
