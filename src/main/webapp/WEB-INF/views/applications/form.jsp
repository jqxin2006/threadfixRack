<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:if test="${ application['new'] }">New </c:if>Application</title>
	
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/authentication.js"></script>

	<c:if test="${ not empty application.defectTracker.id }"> 
		<script>
			var initialDefectTrackerId = <c:out value="${ application.defectTracker.id }"/> 
		</script>
	</c:if>
</head>

<body id="apps">
	<h2><c:if test="${ application['new'] }">New </c:if>Application</h2>
	
<spring:url value="" var="saveUrl"></spring:url>
<form:form modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Name:</td>
				<td class="inputValue">
					<form:input id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="name" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>URL:</td>
				<td class="inputValue">
					<form:input id="urlInput" path="url" size="50" maxlength="255" />
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="url" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Team:</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ application.organization.id }"/>
					</spring:url>
					<a id="organizationText" href="${ fn:escapeXml(orgUrl) }"><c:out value="${ application.organization.name }"/></a>
				</td>
				<td colspan="2">&nbsp;</td>
			</tr>
			<tr>
				<td>Criticality:</td>
				<td class="inputValue">
					<form:select id="criticalityId" path="applicationCriticality.id">
						<form:options items="${applicationCriticalityList}" itemValue="id" itemLabel="name"/>
					</form:select>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="applicationCriticality.id" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	
	<c:if test="${ canSetDefectTracker }">
		<h3>Defect Tracker</h3>
		<table class="dataTable" id="defecttracker">
			<tbody>
		<c:choose>
			<c:when test="${ empty defectTrackerList }">
				<tr>
					<td>Defect Tracker:</td>
					<td class="inputValue">
						No Defect Trackers were found. 
						<c:if test="${ canManageDefectTrackers }">
							<a id="configureDefectTrackersLink" href="<spring:url value="/configuration/defecttrackers/new"/>">Create a Defect Tracker</a>
						</c:if>
					</td>
					<td colspan="2">&nbsp;</td>
				</tr>
			</c:when>
			<c:otherwise>
				<tr>
					<td>Defect Tracker:</td>
					<td class="inputValue">
						<form:select id="defectTrackerId" path="defectTracker.id">
							<form:option value="0" label="<none>"/>
							<form:options items="${defectTrackerList}" itemValue="id" itemLabel="displayName"/>
						</form:select>
						<c:if test="${ canManageDefectTrackers }">
							<a style="padding-left:10px;" id="configureDefectTrackersLink" href="<spring:url value="/configuration/defecttrackers/new"/>">Create a Defect Tracker</a>
						</c:if>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="defectTracker.id" cssClass="errors" />
					</td>
				</tr>
				<tr class="defecttracker_row">
					<td>Username:</td>
					<td class="inputValue">
						<form:input id="username" path="userName" size="50" maxlength="50"/>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="userName" cssClass="errors" />
					</td>
				</tr>
				<tr class="defecttracker_row">
					<td>Password:</td>
					<td class="inputValue">						
						<form:password id="password" showPassword="true" path="password" size="50" maxlength="50" />
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="password" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>
					<spring:url value="/organizations/{orgId}/applications/jsontest" var="testUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						</spring:url>
					<a href="javascript:jsonTest('${ fn:escapeXml(testUrl) }');" id="jsonLink">Test Connection</a>
					</td>
					<td>
					<div id="toReplace">
					</div>
					</td>
				</tr>
				<tr class="defecttracker_row">
					<td id="projectname">Product Name:</td>
					<td class="inputValue">
						<form:select id="projectList" path="projectName">
							<c:if test="${ not empty application.projectName }">
								<option value="${ application.projectName }"><c:out value="${ application.projectName }"/></option>
							</c:if>
						</form:select>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="projectName" cssClass="errors" />
					</td>
				</tr>
			</c:otherwise>
		</c:choose>
			</tbody>
		</table>
		<br/>
	</c:if>
	
	<c:if test="${ canSetWaf }">
		<h3>WAF</h3>
		<table class="dataTable">
		<tbody>
		<spring:url value="/wafs/new" var="newWAFUrl"/>
		<c:choose>
			<c:when test="${ empty wafList }">
				<tr>
					<td>WAF:</td>
					<td class="inputValue">
						No WAFs were found.
						<c:if test="${ canManageWafs }">
							<a id="configureWafsButton" href="${ newWAFUrl }">Create a WAF</a>
						</c:if>
					</td>
					<td colspan="2">&nbsp;</td>
				</tr>
			</c:when>
			<c:otherwise>
				<tr>
					<td>WAF:</td>
					<td class="inputValue">
						<form:select id="wafSelect" path="waf.id">
							<form:option value="0" label="<none>" />
							<form:options items="${ wafList }" itemValue="id" itemLabel="name"/>
						</form:select>
						<c:if test="${ canManageWafs }">
							<a style="padding-left:10px;" id="configureWafsButton" href="${ newWAFUrl }">Create a new WAF</a>
						</c:if>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="waf.id" cssClass="errors" />
					</td>
				</tr>
			</c:otherwise>
		</c:choose>
			</tbody>
		</table>
		<br/>
	</c:if>
	
	<div style="padding-top:8px"> 
	<c:choose>
		<c:when test="${ application['new'] }">
			<input id="addApplicationButton" type="submit" value="Add Application" />
			<spring:url value="/organizations/{orgId}" var="appUrl">
				<spring:param name="orgId" value="${ application.organization.id }" />
			</spring:url>
			<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(appUrl) }">Back to Team <c:out value="${ application.organization.name }"/></a></span>
		</c:when>
		<c:otherwise>
			<c:if test="${ not empty application.defectTracker.id }">
				<input id="updateApplicationButton" type="submit" onclick="if (initialDefectTrackerId && (new Number(initialDefectTrackerId).toString()) !== $('#defectTrackerId').val()) { return confirm('Since you are switching Defect Trackers, you will lose all defects associated with this application.'); }" value="Update Application" />
			</c:if>
			<c:if test="${ empty application.defectTracker.id }">
				<input id="updateApplicationButton" type="submit" value="Update Application" />
			</c:if>
			<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
				<spring:param name="orgId" value="${ application.organization.id }" />
				<spring:param name="appId" value="${ application.id }" />
			</spring:url>
			<span style="padding-left: 10px"><a id="cancelLink" href="${ fn:escapeXml(appUrl) }">Back to Application <c:out value="${ application.name }"/></a></span>
		</c:otherwise>
	</c:choose>
	</div>
</form:form>
</body>