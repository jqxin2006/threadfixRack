<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan Details</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scan_page.js"></script>
</head>

<body id="apps">

	<spring:url value="/organizations/{orgId}" var="orgUrl">
		<spring:param name="orgId" value="${ scan.application.organization.id }" />
	</spring:url>
	<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
		<spring:param name="orgId" value="${ scan.application.organization.id }" />
		<spring:param name="appId" value="${ scan.application.id }" />
	</spring:url>
	<spring:url value="{scanId}/table" var="tableUrl">
		<spring:param name="scanId" value="${ scan.id }"/>
	</spring:url>
	<spring:url value="{scanId}/unmappedTable" var="unmappedTableUrl">
		<spring:param name="scanId" value="${ scan.id }"/>
	</spring:url>
	<spring:url value="/login.jsp" var="loginUrl" />

	<ul class="breadcrumb">
	    <li><a href="<spring:url value="/"/>">Applications Index</a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(orgUrl) }">Team: <c:out value="${ scan.application.organization.name }"/></a> <span class="divider">/</span></li>
	    <li><a href="${ fn:escapeXml(appUrl) }">Application: <c:out value="${ scan.application.name }"/></a><span class="divider">/</span></li>
	    <li class="active"><fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/> <c:out value="${ fn:escapeXml(scan.applicationChannel.channelType.name) }"/> Scan</li>
    </ul>

	<h2><fmt:formatDate value="${ scan.importTime.time }" type="both" dateStyle="short" timeStyle="short"/> 
	<c:out value="${ fn:escapeXml(scan.applicationChannel.channelType.name) }"/> Scan Findings
		<span>
			<a href="#statisticsDiv" data-toggle="collapse" class="btn header-button">Show Statistics</a>
			<a class="btn btn-danger scanDelete header-button" data-delete-form="deleteForm">Delete Scan</a>
		</span>
	</h2>
	
	<spring:url value="{scanId}/delete" var="deleteUrl">
		<spring:param name="scanId" value="${ scan.id }"/>
	</spring:url>
	<form id="deleteForm" method="POST" action="${ fn:escapeXml(deleteUrl) }"></form>

	<div id="helpText">
		This page lists various statistics about a set of scan results from one scan file.<br/>
	</div>
	
	<div class="container-fluid">
		<div id="statisticsDiv" class="row-fluid collapse">
			<div class="span4">
				<h4>Import Statistics</h4>
				<table class="dataTable">
					<tbody>
						<tr>
							<td>Imported Results</td>
							<td class="inputValue">
								<c:out value="${ scan.numberRepeatResults + scan.totalNumberSkippedResults + 
													totalFindings + scan.numWithoutChannelVulns + scan.numWithoutGenericMappings }"/>
							</td>
						</tr>
						<tr>
							<td>Duplicate Results</td>
							<td class="inputValue"><c:out value="${ scan.numberRepeatResults + scan.totalNumberSkippedResults }"/></td>
						</tr>
						<tr>
							<td style="font-weight:bold">Total Findings</td>
							<td class="inputValue"><c:out value="${ totalFindings + 
														scan.numWithoutChannelVulns + scan.numWithoutGenericMappings }"/></td>
						</tr>
					</tbody>
				</table>
			</div>
			<div class="span4">
				<h4>Finding Statistics</h4>
				<table class="dataTable">
					<tbody>
						<tr>
							<td>Findings without Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ scan.numWithoutChannelVulns + scan.numWithoutGenericMappings }"/></td>
						</tr>
						<tr>
							<td>Findings with Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ totalFindings }"/></td>
						</tr>
						<tr>
							<td>Duplicate Findings</td>
							<td class="inputValue"><c:out value="${ totalFindings - vulnData[1] }"/></td>
						</tr>
						<tr>
							<td style="font-weight:bold">Total Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ vulnData[1] }"/></td>
						</tr>
					</tbody>
				</table>
			</div>
			<div class="span4">
				<h4>Vulnerability Statistics</h4>
				<table class="dataTable">
					<tbody>
						<tr>
							<td>New Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ vulnData[2] }"/></td>
						</tr>
						<tr>
							<td>Old Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ vulnData[3] }"/></td>
						</tr>
						<tr>
							<td>Resurfaced Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ vulnData[4] }"/></td>
						</tr>
						<tr>
							<td>Closed Vulnerabilities</td>
							<td class="inputValue"><c:out value="${ vulnData[5] }"/></td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	
		<div class="row-fluid">
			<c:if test="${ totalFindings + scan.numWithoutChannelVulns + scan.numWithoutGenericMappings == 0 }">
				<div id="toReplace">
				<h4>Findings</h4>
				<table class="table table-striped" id="1">
					<thead>
						<tr>
							<th class="first">Severity</th>
							<th>Vulnerability Type</th>
							<th>Path</th>
							<th>Parameter</th>
							<th class="last">Number Merged Results</th>
						</tr>
					</thead>
					<tbody>
						<tr class="bodyRow">
							<c:if test="${ scan.numberRepeatFindings != 0 }">
								<td colspan="6" style="text-align: center;">All Findings were linked to Findings from previous scans.</td>
							</c:if>
							<c:if test="${ scan.numberRepeatFindings == 0 }">
								<td colspan="6" style="text-align: center;">No Findings were found.</td>
							</c:if>
						</tr>
					</tbody>
				</table>
				</div>
			</c:if>
			
			<c:if test="${ totalFindings + scan.numWithoutChannelVulns + scan.numWithoutGenericMappings != 0}">
				<div id="toReplace" class="refreshOnLoad" data-source-url="<c:out value="${ tableUrl }"/>" 
					data-login-url="<c:out value="${ loginUrl }"/>">
				<h4>Mapped Findings</h4>
				<table class="table table-striped" id="1">
					<thead>
						<tr>
							<th class="first">Severity</th>
							<th>Vulnerability Type</th>
							<th>Path</th>
							<th>Parameter</th>
							<th class="last">Number Merged Results</th>
						</tr>
					</thead>
					<tbody>
						<tr class="bodyRow">
							<td colspan="6" style="text-align: center;">Loading Findings.</td>
						</tr>
					</tbody>
				</table>
				</div>
				
				<div id="toReplace2"class="refreshOnLoad" data-source-url="<c:out value="${ unmappedTableUrl }"/>" 
					data-login-url="<c:out value="${ loginUrl }"/>">
				<h4>Unmapped Findings</h4>
				<table class="table table-striped" id="2">
					<thead>
						<tr>
							<th class="first">Severity</th>
							<th>Vulnerability Type</th>
							<th>Path</th>
							<th>Parameter</th>
							<th class="last">Number Merged Results</th>
						</tr>
					</thead>
					<tbody>
						<tr class="bodyRow">
							<td colspan="5" style="text-align: center;">Loading Findings.</td>
						</tr>
					</tbody>
				</table>
				</div>
			</c:if>
		</div>
	</div>
</body>
