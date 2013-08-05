package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertTrue;

import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.ApplicationAddPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.GeneratedReportPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.ReportsIndexPage;
import com.denimgroup.threadfix.selenium.pages.UploadScanPage;

public class ReportTests extends BaseTest {
	public ReportTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

	private RemoteWebDriver driver;

	private static LoginPage loginPage;
	public ApplicationDetailPage applicationDetailPage;
	public UploadScanPage uploadScanPage;
	public TeamIndexPage organizationIndexPage;
	public DashboardPage dashboardPage;
	public TeamDetailPage organizationDetailPage;
	public ReportsIndexPage reportsIndexPage;
	public GeneratedReportPage generatedReportPage;
	public ApplicationAddPage applicationAddPage;

	Random generator = new Random();


	boolean mySQL = true;

	public String appWasAlreadyUploadedErrorText = "Scan file has already been uploaded.";


	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	/*public static URL getScanFilePath(String category, String scannerName,
			String fileName) {
		String string = "SupportingFiles/" + category + "/" + scannerName + "/"
				+ fileName;

		return ClassLoader.getSystemResource(string);// .getFile();
	}*/

	@After
	public void shutDown() {
		driver.quit();
	}

	@Test
	public void navigationTest() {
		String pageText = loginPage.login("user", "password").clickReportsHeaderLink().getH2Tag();
		assertTrue("Reports Page not found", pageText.contains("Reports"));
	}
//reports require manual testing for now, can make automated tests to make sure the webelements generate
//	@Test
//	public void testCreateBasicApplicationnoscan() {
//		String teamName = "testCreateTeam" + getRandomString(5);
//		String appName = "testCreateApp" + getRandomString(5);
//		String urlText = "http://testurl.com";
//
//		// set up an organization
//
//		ReportsIndexPage reportsIndexPage = loginPage.login("user", "password")
//				.clickOrganizationHeaderLink()
//				.clickAddTeamButton()
//				.setTeamName(teamName)
//				.addNewTeam()
//				.addNewApplication(teamName, appName, urlText, "Low")
//				.clickReportsHeaderLink();
//		
//		// Run Trending Report
//		String PageText = driver.findElementByTagName("h2").getText();
//		assertTrue("Reports Page not found", PageText.contains("Reports"));
//		
//		reportsIndexPage = reportsIndexPage.fillAllClickSaveReport("Trending Report",
//				"testCreateApplicationOrg", "testCreateApplicationApp", "HTML");
//		
//		assertTrue("Reports Page not found", reportsIndexPage.isReportPresent());
//
//		// Delete organization and Logout
////		loginPage = reportsIndexPage.clickOrganizationHeaderLink()
////								.expandTeamRowByName(teamName)
////								.clickViewTeamLink()
////								.clickDeleteButton()
////								.logout();
//
//	}
/*
	@Ignore // this test consistenly generates OutOfMemoryErrors on my box. We don't want to screw up all the tests.
	@Test
	public void generateAllReports() throws MalformedURLException {
		String orgName = "testCreateOrg";
		String appName = "testCreataApp";
		String urlText = "http://testurl.com";
		
		//set up an organization
		organizationAddPage = loginPage.login("user", "password").clickOrganizationHeaderLink().clickAddTeamButton();
		
		organizationAddPage.setNameInput(orgName);
		
		boolean first = true;
		
		//add an application
		applicationAddPage = organizationAddPage.clickSubmitButtonValid().clickAddApplicationLink();
		
		applicationAddPage.setNameInput(appName);
		applicationAddPage.setUrlInput(urlText);
		applicationDetailPage = applicationAddPage.clickAddApplicationButton();
		
		
		for (String channel : fileMap.keySet()) {
			if (first) {
				first = false;
				uploadScanPage = applicationDetailPage.clickUploadScanLinkFirstTime()
												 	  .setChannelTypeSelect(channel)
													  .clickAddChannelButton();
													  
			} else {
				uploadScanPage = uploadScanPage.clickAddAnotherChannelLink()
											   .setChannelTypeSelect(channel)
											   .clickAddChannelButton();
			}
		}

		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				File appScanFile = null;
				
				if (System.getProperty("scanFileBaseLocation") == null) {
					appScanFile = new File(new URL(mapEntry.getValue()).getFile());
				} else {
					appScanFile = new File(mapEntry.getValue());
				}
				
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}

			uploadScanPage = uploadScanPage
					// clickAddChannelButton()
					.setFileInput(mapEntry.getValue())
					.setChannelSelect(mapEntry.getKey())
					.clickUploadScanButton()
					.clickUploadScanLink();
					
			uploadScanPage.sleep(1000);
		}
		
		//Navigate to Reports Page
		driver.findElementById("reportsHeader").click();
		ReportsIndexPage reportsIndexPage = new ReportsIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("Reports Page not found", PageText.contains("Reports"));
		
		//Select Options to Run Trending report
		reportsIndexPage.fillAllClickSaveReport("Trending Report","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader = driver.findElementByTagName("span").getText();
		assertTrue("Trending Report not generated",
				pageHeader.contains("Trending Report"));
		sleep(1000);
		
		// Point In time Report
		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		reportsIndexPage.fillAllClickSaveReport("Point in Time Report","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader1 = driver.findElementByTagName("span").getText();
		assertTrue("Point in Time Report not generated",
				pageHeader1.contains("Point in Time Report"));
		sleep(1000);
		
		
		// Vulnerability Progress By type Report
		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		generatedReportPage = reportsIndexPage.fillAllClickSaveReport("Vulnerability Progress By Type","testCreateOrg", "testCreataApp", "HTML");
		String pageHeader2 = driver.findElementByTagName("span").getText();
		assertTrue("Vulnerability Progress By type Report not generated",
				pageHeader2.contains("Vulnerability Progress By Type"));
		sleep(1000);

		// Channel Comparison by Vulnerability Type Report
		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		reportsIndexPage.fillAllClickSaveReport("Channel Comparison By Vulnerability Types","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader3 = driver.findElementByTagName("span").getText();
		assertTrue("Channel Comparison By Vulnerability Type Report not generated",
				pageHeader3.contains("Channel Comparison By Vulnerability Types"));
		
		sleep(1000);

		// Channel Comparison Summary Report
		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		reportsIndexPage.fillAllClickSaveReport("Channel Comparison Summary","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader4 = driver.findElementByTagName("span").getText();
		assertTrue("Channel Comparison Summary Report not generated",
				pageHeader4.contains("Channel Comparison Summary"));
		sleep(1000);	


		// Channel Comparison Detail Report
		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		reportsIndexPage.fillAllClickSaveReport("Channel Comparison Detail","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader5 = driver.findElementByTagName("h2").getText();
		assertTrue("Channel Comparison Detail Report not generated",
				pageHeader5.contains("Channel Comparison Detail"));

		sleep(1000);	

		// Monthly Progress Report

		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		reportsIndexPage.fillAllClickSaveReport("Monthly Progress Report","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader6 = driver.findElementByTagName("span").getText();
		assertTrue("Monthly Progress Report Report not generated",
				pageHeader6.contains("Monthly Progress Report"));

		sleep(1000);	


		//	Portfolio Report

		reportsIndexPage = generatedReportPage.clickReportsHeaderLink();
		reportsIndexPage.fillAllClickSaveReport("Portfolio Report","testCreateOrg", "testCreataApp", "HTML");
		generatedReportPage = new GeneratedReportPage(driver);
		String pageHeader7 = driver.findElementByTagName("h2").getText();
		assertTrue("Portfolio Report not generated",
				pageHeader7.contains("Portfolio Report"));

		sleep(1000);
	}
*/
	/*
	 * This is a smoke test, to be run on a blank database. It adds a bunch of
	 * apps with random criticalities and scan uploads and then tells you what
	 * the basic statistics should be.
	 * 
	 * Requires human checking.
	*/
	
/*
	@Ignore
	@Test
	public void portfolioTest() {
		dashboardPage = loginPage.login("user", "password");

		int numOrgs = 5;
		int numAppsPerOrg = 5;
		String[] orgs = new String[numOrgs];

		Integer[] appsByCriticality = new Integer[] { 0, 0, 0, 0 };
		Integer[] appsNeverScannedByCriticality = new Integer[] { 0, 0, 0, 0 };

		for (int i = 0; i < numOrgs; i++) {
			orgs[i] = getRandomString(20);
			organizationDetailPage = organizationIndexPage
					.clickAddTeamButton().setNameInput(orgs[i])
					.clickSubmitButtonValid();

			for (int j = 0; j < numAppsPerOrg; j++) {
				int index = generator.nextInt(4);
				appsByCriticality[index] += 1;
				applicationDetailPage = organizationDetailPage
						.clickAddApplicationLink()
						.setNameInput(getRandomString(i + 5))
						.setUrlInput("http://dummyurl.com")
						.setCriticalitySelect(criticalities[index])
						.clickAddApplicationButton();

				boolean hasScan = generator.nextBoolean();
				if (hasScan) {
					applicationDetailPage
							.clickUploadScanLinkFirstTime()
							.setChannelTypeSelect(ChannelType.ARACHNI)
							.clickAddChannelButton()
							.setFileInput(
									ScanTests.getScanFilePath("Dynamic",
											"Arachni", "php-demo.xml"))
							.setChannelSelect(ChannelType.ARACHNI)
							.clickUploadScanButton();
				} else {
					appsNeverScannedByCriticality[index] += 1;
				}

				organizationDetailPage = applicationDetailPage
						.clickTeamHeaderLink().clickOrganizationLink(
								orgs[i]);

			}

			organizationIndexPage = organizationDetailPage
					.clickTeamHeaderLink();
		}

		log.debug("Critical: "
				+ (100.0 * appsNeverScannedByCriticality[3] / appsByCriticality[3]));
		log.debug("High: "
				+ (100.0 * appsNeverScannedByCriticality[2] / appsByCriticality[2]));
		log.debug("Medium: "
				+ (100.0 * appsNeverScannedByCriticality[1] / appsByCriticality[1]));
		log.debug("Low: "
				+ (100.0 * appsNeverScannedByCriticality[0] / appsByCriticality[0]));
	}

	private void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	*/
}
