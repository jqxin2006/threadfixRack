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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Scan;

@Service
public class ScanTypeCalculationServiceImpl implements ScanTypeCalculationService {
	
	private final SanitizedLogger log = new SanitizedLogger(ScanTypeCalculationService.class);
	
	private ApplicationDao applicationDao;
	private ApplicationChannelDao applicationChannelDao;
	private ChannelTypeDao channelTypeDao;
	
	@Autowired
	public ScanTypeCalculationServiceImpl(ChannelTypeDao channelTypeDao,
			ApplicationChannelDao applicationChannelDao,
			ApplicationDao applicationDao) {
		this.applicationDao = applicationDao;
		this.applicationChannelDao = applicationChannelDao;
		this.channelTypeDao = channelTypeDao;
	}

	@Override
	public String getScannerType(MultipartFile file) {
		String returnString = null;
		saveFile("tempFile",file);
		
		if (ScanUtils.isZip("tempFile")) {
			returnString = figureOutZip("tempFile");
		} else if (file.getOriginalFilename().endsWith("json")){
			//probably brakeman
			returnString = ChannelType.BRAKEMAN;
		} else {
			returnString = figureOutXml("tempFile");
		}
		
		deleteFile("tempFile");
		
		return returnString;
	}
	
	// We currently only have zip files for skipfish and fortify
	// if we support a few more it would be worth a more modular style
	private String figureOutZip(String fileName) {
		
		String result = null;
		ZipFile zipFile = null;
		try {
			zipFile = new ZipFile(fileName);
			
			if (zipFile.getEntry("audit.fvdl") != null) {
				result = ChannelType.FORTIFY;
			} else {
				for (Enumeration<?> entries = zipFile.entries(); entries.hasMoreElements();) {
					Object entry = entries.nextElement();
					if (entry != null && entry instanceof ZipEntry) {
						String name = ((ZipEntry) entry).getName();
						if (name != null && name.endsWith("issue_index.js")) {
							result = ChannelType.SKIPFISH;
							break;
						}
					}
				}
			}
		} catch (FileNotFoundException e) {
			log.warn("Unable to find zip file.", e);
		} catch (IOException e) {
			log.warn("Exception encountered while trying to identify zip file.", e);
		} finally {
			if (zipFile != null) {
				try {
					zipFile.close();
				} catch (IOException e) {
					log.warn("IOException encountered while trying to close the zip file.", e);
				}
			}
		}
		
		return result;
	}

	private String figureOutXml(String fileName) {
		
		try {
			TagCollector collector = new TagCollector();
			
			InputStream stream = new FileInputStream(fileName);
			
			ScanUtils.readSAXInput(collector, "Done.", stream);
			
			return getType(collector.tags);
		} catch (IOException e) {
			log.error("Encountered IOException. Returning null.", e);
		}
		
		return null;
	}
	
	private static final Set<Entry<String, String[]>> map = new HashSet<>();
	static {
		addToMap(ChannelType.APPSCAN_DYNAMIC, "XmlReport", "AppScanInfo", "Version", "ServicePack", "Summary", "TotalIssues");
		addToMap(ChannelType.ARACHNI, "arachni_report", "title", "generated_on", "report_false_positives", "system", "version", "revision");
		addToMap(ChannelType.BURPSUITE, "issues", "issue", "serialNumber", "type", "name", "host", "path");
		addToMap(ChannelType.NETSPARKER, "netsparker", "target", "url", "scantime", "vulnerability", "url", "type", "severity");
		addToMap(ChannelType.CAT_NET, "Report", "Analysis", "AnalysisEngineVersion", "StartTimeStamp", "StopTimeStamp", "ElapsedTime");
		addToMap(ChannelType.W3AF, "w3afrun");
		addToMap(ChannelType.NESSUS, "NessusClientData_v2");
		addToMap(ChannelType.WEBINSPECT, "Sessions", "Session", "URL", "Scheme", "Host", "Port");
		addToMap(ChannelType.ACUNETIX_WVS,  "ScanGroup", "Scan", "Name", "ShortName", "StartURL", "StartTime");
		addToMap(ChannelType.FINDBUGS, "BugCollection", "Project", "BugInstance", "Class");
		addToMap(ChannelType.APPSCAN_SOURCE, "AssessmentRun", "AssessmentStats" );
		addToMap(ChannelType.NTO_SPIDER, "VULNS", "VULNLIST");
		addToMap(ChannelType.NTO_SPIDER, "VulnSummary");
		addToMap(ChannelType.APPSCAN_ENTERPRISE, "report", "control", "row");
		addToMap(ChannelType.ZAPROXY, "report", "alertitem");
		addToMap(ChannelType.ZAPROXY, "OWASPZAPReport", "site", "alerts");
	}
	
	private static void addToMap(String name, String... tags) { 
		map.add(new SimpleEntry<String, String[]>(name, tags)); 
	}
	
	private String getType(List<String> scanTags) {
		
		for (Entry<String, String[]> entry : map) {
			if (matches(scanTags, entry.getValue())) {
				return entry.getKey();
			}
		}
		
		return null;
	}
	
	private boolean matches(List<String> scanTags, String[] channelTags) {
		
		if (scanTags.size() >= channelTags.length) {
			for (int i = 0; i < channelTags.length; i++) {
				if (!scanTags.get(i).equals(channelTags[i])) {
					return false;
				}
				
				if (i == channelTags.length - 1) {
					return true;
				}
			}
		}
		
		return false;
	}
	
	private void deleteFile(String fileName) {
		File file = new File(fileName);
		if (file.exists() && !file.delete()) {
			log.warn("Something went wrong trying to delete the file.");
			
			file.deleteOnExit();
		} 
	}
	
	public class TagCollector extends DefaultHandler {
		public List<String> tags = new ArrayList<String>();
		private int index = 0;
		
	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
    		if (index++ > 10) {
	    		throw new SAXException("Done.");
	    	}
    		
    		tags.add(qName);
	    }
	}
	
	@Override
	public Integer calculateScanType(int appId, MultipartFile file, String channelIdString) {
		ChannelType type = null;
		
		Integer channelId = -1;
		if (channelIdString != null && !channelIdString.trim().isEmpty()) {
			try {
				channelId = Integer.valueOf(channelIdString);
			} catch (NumberFormatException e) {
				log.error("Provided channelId of '" + channelIdString + "' was not null and was not a number.", e);
			}
		}
		
		if (channelId == null || channelId == -1) {
			String typeString = getScannerType(file);
			if (typeString != null && !typeString.trim().isEmpty()) {
				type = channelTypeDao.retrieveByName(typeString);
			} else {
				return null;
			}
		} else {
			type = channelTypeDao.retrieveById(channelId);
		}
		
		if (type != null) {
			ApplicationChannel channel = applicationChannelDao.retrieveByAppIdAndChannelId(
					appId, type.getId());
			if (channel != null) {
				return channel.getId();
			} else {
				Application application = applicationDao.retrieveById(appId);
				channel = new ApplicationChannel();
				channel.setChannelType(type);
				application.getChannelList().add(channel);
				channel.setApplication(application);
				channel.setScanList(new ArrayList<Scan>());
				
				channel.setApplication(application);
				if (!isDuplicate(channel)) {
					applicationChannelDao.saveOrUpdate(channel);
					return channel.getId();
				}
			}
		}
		return null;
	}
	
	public boolean isDuplicate(ApplicationChannel applicationChannel) {
		if (applicationChannel.getApplication() == null
				|| applicationChannel.getChannelType().getId() == null) {
			return true; 
		}
		
		ApplicationChannel dbAppChannel = applicationChannelDao.retrieveByAppIdAndChannelId(
				applicationChannel.getApplication().getId(), applicationChannel.getChannelType()
						.getId());
		return dbAppChannel != null && !applicationChannel.getId().equals(dbAppChannel.getId());
	}
	
	@Override
	public String saveFile(Integer channelId, MultipartFile file) {
		if (channelId == null || file == null) {
			log.warn("The scan upload file failed to save, it had null input.");
			return null;
		}
		
		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);
		
		if (applicationChannel == null) {
			log.warn("Unable to retrieve Application Channel - scan save failed.");
			return null;
		}
		
		if (applicationChannel.getScanCounter() == null)
			applicationChannel.setScanCounter(1);
		
		String inputFileName = "scan-file-" + applicationChannel.getId() + "-" + applicationChannel.getScanCounter();

		applicationChannel.setScanCounter(applicationChannel.getScanCounter() + 1);
		
		applicationChannelDao.saveOrUpdate(applicationChannel);
		
		return saveFile(inputFileName,file);
	}
	
	private String saveFile(String inputFileName, MultipartFile file) {
		InputStream stream = null;
		try {
			stream = file.getInputStream();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		if (stream == null) {
			log.warn("Failed to retrieve an InputStream from the file upload.");
			return null;
		}
		
		File diskFile = new File(inputFileName);
		FileOutputStream out = null;
		try {
			out = new FileOutputStream(diskFile);

			byte[] buf = new byte[1024];
			int len = 0;

			while ((len = stream.read(buf)) > 0) {
				out.write(buf, 0, len);
			}

			out.close();
		} catch (IOException e) {
			log.warn("Writing the file stream to disk encountered an IOException.", e);
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				log.warn("IOException encountered while attempting to close a stream.", e);
			}
			if (out != null) {
				try {
					out.close();
				} catch (IOException e) {
					log.warn("IOException encountered while attempting to close a stream.", e);
				}
			}
		}
		
		return inputFileName;
	}
}
