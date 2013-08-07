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
// Added by Michael Xin
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.channel;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.commons.lang.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 *
 */
public class ProductSecurityTestChannelImporter extends AbstractChannelImporter {
	private static final String NEW_LINE = "bbcc5220-4a23";
	private static final String NEW_WHITESPACE = "761d3ebb-09f2";
	private static final String NEW_TAB = "75fb4322-03b9";
	private static final String DOUBLE_SQUARE = "d0781cea-e089";
	
	@Autowired
	public ProductSecurityTestChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.PRODUCT_SECURITY_TEST);
		
		doSAXExceptionCheck = false;
	}

	@Override
	public Scan parseInput() {
		cleanInputStream();
		return parseSAXInput(new ProductSecurityTestSAXParser());
	}
	
	public void cleanInputStream() {
		if (inputStream == null)
			return;
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		
		String line = null, fullString = "";
		try {
			StringBuffer buffer = new StringBuffer();
			while ((line = reader.readLine()) != null) {
				while (line.contains("]]]"))
					line = line.replace("]]]", "] ]]");
				buffer.append(line);
			}
			fullString = buffer.toString();
		} catch (IOException e) {
			log.warn("IOException while trying to clean input stream", e);
		}
		
		try {
			reader.close();
		} catch (IOException e) {
			log.warn("IOException while trying to close file input stream.", e);
		}
		
		inputStream = new ByteArrayInputStream(fullString.getBytes());
	}

	public class ProductSecurityTestSAXParser extends HandlerWithBuilder {
		
		private boolean getChannelVulnText    = false;
		private boolean getPathText            = false;
		private boolean getParamText          = false;
		private boolean getSeverityText       = false;
		private boolean getSerialNumber       = false;
		private boolean getLongDescription    = false;
		
		private String currentChannelVulnCode = null;
		private String currentPathText         = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
		private String currentSerialNumber    = null;
		private String currentLongDescription = null;
		
		private void add(Finding finding) {
			if (finding != null) {
				if (currentSerialNumber != null) {
					finding.setNativeId(currentSerialNumber);
				} else {
					finding.setNativeId(getNativeId(finding));
				}
				
	    		finding.setIsStatic(false);
	    		saxFindingList.add(finding);
    		}
		}

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("type".equals(qName)) {
	    		getChannelVulnText = true;
	    	} else if ("path".equals(qName)) {
	    		getPathText = true;
	    	} else if ("serialNumber".equals(qName)) {
	    		getSerialNumber = true;
	    	}  else if ("severity".equals(qName)) {
	    		getSeverityText = true;
	    	} else if ("issues".equals(qName)) {
	    		date = getCalendarFromString("EEE MMM dd kk:mm:ss zzz yyyy", 
	    				atts.getValue("testTime"));
	    	} else if ("parameter".equals(qName)) {
	    		getParamText = true;
	    	} else if ("longDescription".equals(qName)){
	    		getLongDescription = true;
	    	}
	    	
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getBuilderText();
	    		if (currentChannelVulnCode != null){
	    		currentChannelVulnCode = currentChannelVulnCode.trim();
	    		}
	    		getChannelVulnText = false;
	    	} else if (getPathText) {
	    		currentPathText = getBuilderText();
	    		if (currentPathText != null){
	    		currentPathText = currentPathText.trim();
	    		}
	    		getPathText = false;
	    	}
	    	 else if (getParamText) {
	    		currentParameter = getBuilderText();
	    		if (currentParameter != null){
	    		currentParameter = currentParameter.trim();
	    		}
	    		getParamText = false;
	    	} else if (getSerialNumber) {
	    		currentSerialNumber = getBuilderText();
	    		if (currentSerialNumber != null){
	    		currentSerialNumber = currentSerialNumber.trim();
	    		}
	    		getSerialNumber = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getBuilderText();
	    		if (currentSeverityCode!=null){
	    		    currentSeverityCode = currentSeverityCode.trim();
	    		}
	    		getSeverityText = false;
	    	} else if (getLongDescription){
	    		currentLongDescription = getBuilderText();
	    		currentLongDescription = currentLongDescription.replaceAll(NEW_LINE, "\n");
	    		currentLongDescription = currentLongDescription.replaceAll(NEW_WHITESPACE, " ");
	    		currentLongDescription = currentLongDescription.replaceAll(NEW_TAB, "\t");
	    		currentLongDescription = currentLongDescription.replaceAll(DOUBLE_SQUARE, "]]");
	    		
	    		getLongDescription = false;
	   	
	    	}
	    	
	    	if ("issue".equals(qName)) {
	    		
	    		
	    		Finding finding = constructFinding(currentPathText, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		finding.setLongDescription(currentLongDescription);
	    		
	    		//log.info("The finding with path:" + currentPathText + "; Parameter:" +
						//currentParameter + "; Code:" + currentChannelVulnCode + ";severity:" + 
	    				//		currentSeverityCode + ";Description:" + currentLongDescription);
	    		
	    		add(finding);
	    		
	    		currentChannelVulnCode = null;
	    		currentSeverityCode    = null;
	    		currentParameter       = null;
	    		currentPathText         = null;
	    		currentSerialNumber    = null;
	    		currentLongDescription = null;
	    		
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getChannelVulnText || getPathText  || getParamText || 
	    			getSeverityText ||  getSerialNumber || getLongDescription) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new ProductSecurityTestSAXValidator());
	}
	
	public class ProductSecurityTestSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if (ScanImportStatus.SUCCESSFUL_SCAN == testStatus && !hasFindings)
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void endDocument() {
	    	setTestStatus();
	    }

	    public void startElement (String uri, String name, String qName, Attributes atts) 
	    		throws SAXException {	    	
	    	if ("issues".equals(qName)) {
	    		testDate = getCalendarFromString("EEE MMM dd kk:mm:ss zzz yyyy", 
	    				atts.getValue("testTime"));
	    		if (testDate != null)
	    			hasDate = true;
	    		correctFormat = atts.getValue("ProductSecurityTestVersion") != null;
	    	}
	    	
	    	if ("issue".equals(qName)) {
	    		hasFindings = true;	
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
}
