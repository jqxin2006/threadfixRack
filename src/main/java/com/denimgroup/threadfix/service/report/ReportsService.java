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
package com.denimgroup.threadfix.service.report;

import javax.servlet.http.HttpServletRequest;

import org.springframework.ui.Model;

import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.webapp.controller.ReportCheckResultBean;


/**
 * @author drivera
 * 
 */
public interface ReportsService {
	
	enum ReportCheckResult {
		VALID("Valid"), 
		NO_APPLICATIONS("No Applications"), 
		BAD_REPORT_TYPE("Bad Report Type"), 
		IO_ERROR("IO Error"),
		OTHER_ERROR("Unable to generate report.");
		
		private String text;
		
		ReportCheckResult(String text) { this.text = text; }
		public String toString() { return text; }
	}
	
	ReportCheckResultBean generateReport(ReportParameters parameters, HttpServletRequest request);

	String scannerComparisonByVulnerability(Model model,
			ReportParameters reportParameters);
}
