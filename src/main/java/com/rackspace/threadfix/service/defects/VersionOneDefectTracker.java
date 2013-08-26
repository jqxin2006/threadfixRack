package com.rackspace.threadfix.service.defects;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.StringReader;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.net.ssl.SSLHandshakeException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.versionone.om.V1Instance;
import com.versionone.om.V1InstanceGetter;
import com.versionone.om.AssetID;
import com.versionone.om.Project;
import com.versionone.om.filters.ProjectFilter;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectMetadata;
import com.denimgroup.threadfix.service.defects.ProjectMetadata;
import com.denimgroup.threadfix.service.SanitizedLogger;


public class VersionOneDefectTracker extends AbstractDefectTracker {

    private static String V1_REST_ENDPOINT = "rest-1.v1";
    private V1Instance v1;
    // targetProject is the selected child project (in component) or the parent project if parent do not have children
    private Project targetProject;    
    private Project childProject;
    private String url = null;
    private String username; 
    private String password; 
    private static String jdbcPropertiesFile = "jdbc.properties";
    private static Properties jdbcProperties = new Properties();
    private static String JDBC_DRIVER; 
    private static String DB_URL; 
    private static String USER; 
    private static String PASS; 
    private static Connection conn;
    private static PreparedStatement preparedStatementLongDesc;
    private static PreparedStatement preparedStatementProjNames;
    private static PreparedStatement preparedStatementSeverity;
    private static String longDescSQL = "select F.LONGDESCRIPTION, F.ID from FINDING F, SURFACELOCATION S where S.id = F.surfacelocationid and S.parameter = ? and S.path = ?";
    private static String projectNamesSQL = "select name from application order by name";
    private static String severitySQL = "select gs.name from finding f, vulnerability v, genericseverity gs where f.vulnerabilityid = v.id and v.genericseverityid = gs.id and f.id = ?";
    private static String projs;
    static org.apache.commons.logging.Log logger = org.apache.commons.logging.LogFactory.getLog(VersionOneDefectTracker.class);
    
    static {
        
        if (jdbcProperties.isEmpty()) {
            logger.info("-- loading jdbc properties");
            try {
                InputStream inputStream = VersionOneDefectTracker.class.getClassLoader().getResourceAsStream(jdbcPropertiesFile);
                if (inputStream == null) {
                    logger.error("file '" + jdbcPropertiesFile + "' not found in the classpath");
                }
                jdbcProperties.load(inputStream);
            }
            catch(Exception e) {
                logger.error("Exception loading jdbc properties " + e);
            }
        }
        logger.info("loaded " + jdbcProperties.size() + " properties from " + jdbcPropertiesFile);
        
        connectToDatabase();
        prepareStatementLongDesc();
        prepareStatementProjNames();
        prepareStatementSeverity();
        populateProjectNamesFromDB();
    }

	
    /*
	 * You can implement only parts of this class and have functional integration.
	 * 
	 * If you assume valid input, return true from all three hasValid... methods.
	 * 
	 * If you don't care about error messages when submission fails, return a string literal from getTrackerError()
	 * 
	 * Static options can be used in getProjectMetadata, just expand on the code that's already there. 
	 * Not all of the fields need to be implemented.
	 * 
	 * You could also get away with returning string literals from getProductNames() and getProjectIdByName() if they 
	 * don't change often or you are tracking only certain applications.
	 * 
	 * getBugUrl is purely for convenience when viewing the defect page.
	 * 
	 * createDefect() is obviously the most important. If you only need to export, just implement that.
	 * 
	 * getMultipleDefectStatus is only necessary if you want changes to appear in ThreadFix.
	 * 
	 */
	@Override
	public String createDefect(List<Vulnerability> vulnerabilities,
			DefectMetadata metadata) {
	    log.info(">>>  Entering createDefect");
		
        AssetID aid = null;
        Project p = getProjectByName();
		for (Vulnerability vulnerability : vulnerabilities) {
            String vulnerabilityName = "";
            String vulnerabilityId = "";
            if (vulnerability.getGenericVulnerability() != null) {
                if (vulnerability.getGenericVulnerability().getName() != null) {
                    vulnerabilityName = vulnerability.getGenericVulnerability().getName();
                    log.info("vulnerability.getGenericVulnerability().getName()=" + vulnerabilityName);
                }
                if (vulnerability.getGenericVulnerability().getId() != null) {
                    vulnerabilityId = "" + vulnerability.getGenericVulnerability().getId();
                    log.info("vulnerability.getGenericVulnerability().getId()=CWE-ID " + vulnerabilityId);
                }
            }
            String path = "";
            String param = "";
            String url = "";
            if (vulnerability.getSurfaceLocation() != null) {
                if (vulnerability.getSurfaceLocation().getPath() != null) {
                    path = vulnerability.getSurfaceLocation().getPath();
                    log.info("vulnerability.getSurfaceLocation().getPath()=" + path);
                }
                if (vulnerability.getSurfaceLocation().getParameter() != null) {
                    param = vulnerability.getSurfaceLocation().getParameter();
                    log.info("vulnerability.getSurfaceLocation().getParameter()=" + param);
                }
                if (vulnerability.getSurfaceLocation().getUrl() != null) {
                    url = vulnerability.getSurfaceLocation().getUrl().toString();
                    log.info("vulnerability.getSurfaceLocation().getUrl()=" + url);
                }
            }
        
            String component = "";
            if (metadata.getComponent() != null) {
                component = metadata.getComponent();
                log.info(" -- selected component=" + component);
                String childProjectName = component;
                v1 = getV1Instance();
                V1InstanceGetter v1getter = v1.get();
                targetProject = v1getter.projectByName(childProjectName);
            }         

            DescAndFindingID df = getLongDescription(param, path);
            String longDescription = df.longDescription;
            int findingId = df.findingId;
            if (longDescription != null  &&  !longDescription.equals("")) {
                String severityPS = translateSeverity(getSeverity(findingId));
                StringBuilder ldesc = new StringBuilder(longDescription);
                editDescription(ldesc, "\n", "<br>");
                com.versionone.om.Defect d = targetProject.createDefect("Product_Security - " +
                                                            severityPS + " - " +
                                                            getProjectName() + " - " +
                                                            path + " - " +
                                                            vulnerabilityName);
                d.setDescription(ldesc.toString());
                d.setFoundBy("Product Security");
                aid = d.getID();
                d.save();
                log.info(">>>  Exiting createDefect - success");
                return aid.getToken();
            }
		}
        
	    log.info(">>>  Exiting createDefect - fail");
		return "";
	}

    
	@Override
	public String getBugURL(String endpointURL, String bugID) {
		// Here you want to return the URL that points to the bug page. Something like
		// return endpointURL + "/xmlrpc.cgi?bugId=" + bugID;
	    log.info(">>>  Entering getBugURL");
		
        if (endpointURL != null)
            log.info(" --endpointURL=" + endpointURL);
        if (endpointURL != null)
            log.info(" --bugID=" + bugID);

	    log.info(">>>  Exiting getBugURL");
		return null;
	}

    
	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
	    log.info(">>>  Entering getMultipleDefectStatus");
		Map<Defect, Boolean> returnMap = new HashMap<Defect, Boolean>();
		
		// Find the open or closed status for each defect.
		if (defectList != null && defectList.size() != 0) {
			log.info("Updating VersionOne defect status for " + defectList.size() + " defects.");
            v1 = getV1Instance();
            V1InstanceGetter v1getter = v1.get();
            String status = null;
            for (Defect defect : defectList) {
                if (defect != null) {
                    // do whatever to get the status
                    status = getStatus(defect, v1getter);
                    log.info(" defect status = " + status);
                    if ( !status.equals("Done") ) {
                        log.info(" defect is open");
                        returnMap.put(defect, true); 
                        //defect.setStatus("Actual Status"); // ASSIGNED / RESOLVED / CLOSED / etc.
                        // This will be displayed as the status for the defect
                    }
                    else {
                        log.info(" defect is closed");
                        returnMap.put(defect, false);
                    }
                }
            }
		} else {
			log.info("Tried to update defects but no defects were found.");
		}
		
	    log.info(">>>  Exiting getMultipleDefectStatus");
		return returnMap;
	}
    
    
	private String getStatus(Defect defect, V1InstanceGetter v1getter) {
	    log.info(">>>  Entering getStatus");
        if (defect == null) {
            log.info(" defect is null");
            return "";
        }
        String v1defectId = defect.getNativeId();
        if (v1defectId == null) {
            log.info(" v1defectId is null");
            return "";
        }
        com.versionone.om.Defect v1defect = v1getter.defectByID(v1defectId);
        if (v1defect == null) {
            log.info(" v1defect is null");
            return "";
        }
        com.versionone.om.IListValueProperty prop = v1defect.getStatus();
        if (prop == null) {
            log.info(" prop is null");
            return "";
        }
        if (prop != null) {
            log.info(" prop.getCurrentValue=" + prop.getCurrentValue());
            return prop.getCurrentValue();
        }
        log.info(">>>  Exiting getStatus");
        return "";
    }
    
    
	@SuppressWarnings("unused")
	@Override
	public String getProductNames() {
	    log.info(">>>  Entering getProductNames");
		
		// In this method you will have a username and password that the user configured as well as
		// the endpoint URL that was previously configured. These can be accessed with
		
		String usernameToSubmit = getUsername();
		String passwordToSubmit = getPassword();
		String urlToUse = getUrl();
		
		// Do whatever to get the product names, then concatenate them together with commas separating them
				
		// If you use the setLastError method and return null, 
		// the user will be presented with the passed string as an error message.
		//setLastError("The request for product names failed because the credentials are incorrect.");
		
		//return "Comma,Separated,Product Names";

        if (projs == null) {
            log.error("-- something is wrong.  product list is empty");
        }
        
	    log.info(">>>  Exiting getProductNames");
        return projs;
	}

    
	@Override
	public String getProjectIdByName() {
		// In this method, in addition to getUsername(), getPassword(), and getUrl(), 
		// getProjectName() should return a valid product name.
		// Your job is to use this information to find the corresponding ID.
		// If you do not have separate names and IDs, just use the name.
		// maybe do web requests
		
	    log.info(">>>  Entering getProjectIdByName");
		log.info("Finding id for project " + getProjectName());
		
        //Project p = getProjectByName();
        //if (p != null) {
        //    AssetID aid = p.getID();
        //    log.info(" project id=" + aid.getToken());
        //    return aid.getToken();
        //}

        //return "";
	    log.info(">>>  Exiting getProjectIdByName");
        return getProjectId();
	}

    
	@Override
	public ProjectMetadata getProjectMetadata() {
	    log.info(">>>  Entering getProjectMetadata");
		
		// This method is a little trickier than the previous ones.
		// You will have username, password, url, projectname, and projectid.
		// either make a request or populate lists in code and return a ProjectMetadata object.
		// The values you present here are options that the user will select that will then come back
		// in the defectmetadata object for createDefect().
		
        List<String> blankList = Arrays.asList(new String[] {"-"});
		List<String> statuses = new ArrayList<String>();
		List<String> components = new ArrayList<String>();
		List<String> severities = new ArrayList<String>();
		List<String> versions = new ArrayList<String>();
		List<String> priorities = new ArrayList<String>();
		
        String projectName = getProjectName();
        if (projectName != null) {
            v1 = getV1Instance();
            V1InstanceGetter v1getter = v1.get();
            Project parentProj = v1getter.projectByName(projectName);
            if (parentProj != null) {
                ProjectFilter filter = new ProjectFilter();
                Collection<Project> childrenProjs = parentProj.getChildProjects(filter);
                for (Project p : childrenProjs) {
                    components.add(p.getName());
                }
            }
            if (components.size() == 0) {
                log.info(" parent project do not have children!  setting component as the parent!");
                components.add(parentProj.getName());
            }
        }
		log.info("-- After populating components");
		
		statuses.add("-");
		severities.add("-");
		versions.add("-");
        priorities.add("-");
		
	    log.info(">>>  Exiting getProjectMetadata");
		return new ProjectMetadata(components, blankList, blankList, statuses, priorities);
	}

    
	@Override
	public String getTrackerError() {
		// When a defect submission fails, this method is used to update the JobStatus with the correct
		// error message. Not absolutely necessary.
	    log.info(">>>  Entering getTrackerError");
		log.info("Returning the error from the tracker.");
	    log.info(">>>  Exiting getTrackerError");
		return "The tracker failed to export a defect.";
	}

    
	@Override
	public boolean hasValidCredentials() {
		// getUrl(), getPassword(), and getUsername will work here.
		// Given those, check the credentials for validity.
	    log.info(">>>  Entering hasValidCredentials");
        
        try {
            v1 = new V1Instance(getUrl(), getUsername(), getPassword());
        }
        catch(Exception e) {
            log.info(">>>  Exiting hasValidCredentials");
            return false;
        }
        
        log.info(">>>  Exiting hasValidCredentials");
		return true;
	}

    
	@Override
	public boolean hasValidProjectName() {
		// getProjectName() as well as credentials and the URL are available here.
		// this is used to check server-side that the user picked a valid option from the drop-down.
	    log.info(">>>  Entering hasValidProjectName");
		log.info("Checking Project Name.");
        
        Project p = getProjectByName();
        if (p != null) {
            log.info(">>>  Exiting hasValidProjectName : true");
            return true;
        }
        else {
            log.info(">>>  Exiting hasValidProjectName : false");
            return false;
        }
	}

    
	@Override
	public boolean hasValidUrl() {
		// Given only getUrl(), make sure that there is a valid endpoint that you can use.
	    log.info(">>>  Entering hasValidUrl");
		
		if (getUrlWithRest() == null) {
			log.info("URL was invalid.");
            log.info(">>>  Exiting hasValidUrl : false");
			return false;
		}

        log.info(">>>  Exiting hasValidUrl : true");
		return true;
	}
    
    
	private String getUrlWithRest() {
	    log.info(">>>  Entering getUrlWithRest");
		if (getUrl() == null || getUrl().trim().equals("")) {
			return null;
		}
		
		try {
			new URL(getUrl());
		} catch (MalformedURLException e) {
			setLastError("The URL format was bad.");
			return null;
		}
        
		if (getUrl().endsWith(V1_REST_ENDPOINT + "/")) {
			return getUrl();
		}
        
		if (getUrl().endsWith(V1_REST_ENDPOINT)) {
			return getUrl() + "/";
		}
		
		String tempUrl = getUrl().trim();
		if (tempUrl.endsWith("/")) {
			tempUrl = tempUrl.concat(V1_REST_ENDPOINT + "/");
		} else {
			tempUrl = tempUrl.concat("/" + V1_REST_ENDPOINT + "/");
		}
        
	    log.info(">>>  Exiting getUrlWithRest");
		return tempUrl;
	}
    
    
	private com.versionone.om.Project getProjectByName() {
		// In this method, in addition to getUsername(), getPassword(), and getUrl(),
		// getProjectName() should return a valid product name.
		// Your job is to use this information to find the corresponding ID.
		// If you do not have separate names and IDs, just use the name.
		
	    log.info(">>>  Entering getProjectByName");
		log.info("Finding project " + getProjectName());
        
        v1 = getV1Instance();
        V1InstanceGetter v1getter = v1.get();
        Project p = v1getter.projectByName(getProjectName());
        if (p != null)
            return p;
		
        /* Project p = null;
        Iterator<Project> it = rootProjects.iterator();
        for (; it.hasNext();) {
            p = it.next();
            log.info("found proj=" + p.getName());
            if (p.getName().equals(getProjectName())) {
                log.info("returning proj=" + p.getName());
                return p;
            }
        } */
        
        log.info("-- getProjectByName is returning null!!!");
	    log.info(">>>  Exiting getProjectByName");
        return null;
	}
    
    
	private V1Instance getV1Instance() {
	    log.info(">>>  Entering getV1Instance");
		log.info("Getting v1 instance ");
        
        if (v1 == null) {
            try {
                v1 = new V1Instance(getUrl(), getUsername(), getPassword());
                log.info("-- Successfully connected to v1 in getV1Instance");
            }
            catch(Exception e) {
                setLastError("Unable to connect to V1 server.");
                log.error("-- Exception getting connection obj v1 in getV1Instance");
                throw new RuntimeException("Exception getting connection obj v1 in getV1Instance");
            }
        }
        
	    log.info(">>>  Exiting getV1Instance");
        return v1;
    }
    
    
    private static void connectToDatabase() {
	    logger.info(">>>  Entering connectToDatabase");
        
        if (conn == null) {
            try {
                JDBC_DRIVER = jdbcProperties.getProperty("jdbc.driverClassName");
                Class.forName(JDBC_DRIVER);
                
                USER = jdbcProperties.getProperty("jdbc.username");
                PASS = jdbcProperties.getProperty("jdbc.password");
                DB_URL = jdbcProperties.getProperty("jdbc.url");
                conn = DriverManager.getConnection(DB_URL, USER, PASS);
                logger.info("Connected database successfully...");
            }catch(SQLException se){
                logger.error("-- got exception getting prepared stmt db");
                se.printStackTrace();
            }catch(Exception e){
                logger.error("-- got exception connecting to db");
                e.printStackTrace();
            }
        }
        
	    logger.info(">>>  Exiting connectToDatabase");
    }

    
    private static void prepareStatementLongDesc() {
	    logger.info(">>>  Entering prepareStatementLongDesc");
        
        if (preparedStatementLongDesc == null) {
            try {
                connectToDatabase();
                preparedStatementLongDesc = conn.prepareStatement(longDescSQL);
            }catch(SQLException se){
                logger.error("-- got exception getting prepared stmt db for long desc");
                se.printStackTrace();
            }catch(Exception e){
                logger.error("-- got exception connecting to db for long desc");
                e.printStackTrace();
            }
        }
        
	    logger.info(">>>  Exiting prepareStatementLongDesc");
    }
    
    
    private static void prepareStatementProjNames() {
	    logger.info(">>>  Entering prepareStatementProjNames");
        
        if (preparedStatementProjNames == null) {
            try {
                connectToDatabase();
                preparedStatementProjNames = conn.prepareStatement(projectNamesSQL);
            }catch(SQLException se){
                logger.error("-- got exception getting prepared stmt db for proj names");
                se.printStackTrace();
            }catch(Exception e){
                logger.error("-- got exception connecting to db for proj names");
                e.printStackTrace();
            }
        }
        
	    logger.info(">>>  Exiting prepareStatementProjNames");
    }
    
    
    private static void prepareStatementSeverity() {
	    logger.info(">>>  Entering prepareStatementSeverity");
        
        if (preparedStatementSeverity == null) {
            try {
                connectToDatabase();
                preparedStatementSeverity = conn.prepareStatement(severitySQL);
            }catch(SQLException se){
                logger.error("-- got exception getting prepared stmt db for severity");
                se.printStackTrace();
            }catch(Exception e){
                logger.error("-- got exception connecting to db for severity");
                e.printStackTrace();
            }
        }
        
	    logger.info(">>>  Exiting prepareStatementSeverity");
    }
    
    
    private String getSeverity(int findingId) {
	    logger.info(">>>  Entering getSeverity");
        logger.info(" findingId=" + findingId);
        
        String genericSeverity = "";
        try {
            prepareStatementSeverity();
            preparedStatementSeverity.setInt(1, findingId);
            ResultSet rs = preparedStatementSeverity.executeQuery();
            while (rs.next()) {
                genericSeverity = rs.getString(1);
                logger.info(" genericSeverity=" + genericSeverity);
                return genericSeverity;
            }
        }catch(Exception e){
            logger.error("-- got exception reading generic severity from db " + e);
            e.printStackTrace();
        }
        
	    logger.info(">>>  Exiting getSeverity");
        return "";
    }
    
    
    private String translateSeverity(String genericSeverity) {
	    logger.info(">>>  Entering translateSeverity with genericSeverity=" + genericSeverity);
        String severityPS = "";
        
        if (genericSeverity.equals("Critical"))
            severityPS = "S0";
        else if (genericSeverity.equals("High"))
            severityPS = "S1";
        else if (genericSeverity.equals("Medium"))
            severityPS = "S2";
        else if (genericSeverity.equals("Low"))
            severityPS = "S3";
        else
            severityPS = "Unknown";
        
	    logger.info(">>>  Exiting translateSeverity");
        return severityPS;
    }
    
    
    private DescAndFindingID getLongDescription(String param, String path) {
	    logger.info(">>>  Entering getLongDescription with param=" + param + " path=" + path);
        
        String longDescription = "";
        int findingId = -1;
        try {
            prepareStatementLongDesc();
            preparedStatementLongDesc.setString(1, param);
            preparedStatementLongDesc.setString(2, path);
            ResultSet rs = preparedStatementLongDesc.executeQuery();
            while (rs.next()) {
                longDescription = rs.getString("LONGDESCRIPTION");
                findingId = rs.getInt("ID");
                log.info("  findingId=" + findingId);
                return new DescAndFindingID(longDescription, findingId);
            }
        }catch(Exception e){
            log.error("-- got exception reading desc from db " + e);
            e.printStackTrace();
        }
        
	    logger.info(">>>  Exiting getLongDescription");
        return null;
    }
    
    
    private void editDescription(StringBuilder input, String from, String to) {
	    logger.info(">>>  Entering editDescription");
		
        int index = input.indexOf(from);
        while (index != -1)
        {
            input.replace(index, index + from.length(), to);
            index += to.length(); 
            index = input.indexOf(from, index);
        }
        
	    logger.info(">>>  Exiting editDescription");
    }
    
    
	private synchronized static void populateProjectNamesFromDB() {
	    logger.info(">>>  Entering populateProjectNamesFromDB");
                
        StringBuilder sb = new StringBuilder("System (All Projects),");
        sb.append("testprojectbtv,");
        try {
            String projName = "";
            ResultSet rs = preparedStatementProjNames.executeQuery(projectNamesSQL);
            while (rs.next()) {
                projName = rs.getString("NAME");
                sb.append(projName + ",");
            }
        }catch(Exception e){
            logger.error("-- got exception reading proj name from db " + e);
            e.printStackTrace();
        }
        projs = sb.toString();
        projs = projs.substring(0, projs.length()-1);
        
	    logger.info(">>>  Exiting populateProjectNamesFromDB");
        return;
	}
    
    
    class DescAndFindingID {
        DescAndFindingID(String longDescription, int findingId) {
            this.longDescription = longDescription;
            this.findingId = findingId;
        }
        String longDescription;
        int findingId;
    }
}