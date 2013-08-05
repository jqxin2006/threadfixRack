<%@ include file="/common/taglibs.jsp"%>

<head>
	<title><c:out value="${ waf.name }"/></title>
</head>

<body id="wafs">
	<h2 id="nameText" ><c:out value="${ waf.name }"/></h2>

	<div id="helpText">
		This page is used to generate rules and upload WAF logs to correlate their results with your existing Vulnerabilities.
		<c:if test="${ empty waf.applications }"><br/>To get started, link this WAF to an application in either the New Application or Edit Application pages.</c:if>
	</div>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Type:</td>
				<td id="wafTypeText" class="inputValue"><c:out value="${ waf.wafType.name }"/></td>
			</tr>
		</tbody>
	</table>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	
	<c:if test="${ not hasApps }">
		<div class="alert alert-error" style="margin-top:10px;">
			You need to attach an Application to this WAF before you can start to generate rules.
		</div>
	</c:if>
	
	<c:if test="${ canManageWafs and not empty waf.wafRules and hasApps }">
		<spring:url value="/wafs/${waf.id}/upload" var="uploadUrl">
			<spring:param name="wafId" value="${ waf.id }"/>
		</spring:url>
		<form:form method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
			<form:errors path="*" cssClass="errors" />
			<table class="dataTable">
				<tbody>
					<tr>
						<td>Log File:</td>
						<td class="inputValue">
							<input type="file" name="file" size="50" />
						</td>
					</tr>
				</tbody>
			</table>
			<br />
			<input class="btn btn-primary" type="submit" value="Upload File"/>
			<span style="padding-left: 10px"><a href="<spring:url value="/wafs"/>">Cancel</a></span>
		</form:form>
	</c:if>

	<c:if test="${hasApps}">

		<h3>Applications</h3>
		<table class="table table-striped">
			<thead>
				<tr>
					<th class="medium first">Name</th>
					<th class="long last">URL</th>
				</tr>
			</thead>
			<tbody id="applicationsTableBody">
		<c:choose>
			<c:when test="${ not empty apps }">
				<c:forEach var="app" items="${ apps }">
					<c:if test="${ app.active }">
					<tr class="bodyRow">
						<td>
							<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
								<spring:param name="orgId" value="${ app.organization.id }"/>
								<spring:param name="appId" value="${ app.id }"/>
							</spring:url>
							<a href="${ fn:escapeXml(appUrl) }"><c:out value="${ app.name }"/></a>
						</td>
						<td><c:out value="${ app.url }"/></td>
					</tr>
					</c:if>
				</c:forEach>
			</c:when>
			<c:otherwise>
				<tr class="bodyRow">
					<td colspan="2" style="text-align:center;">No applications found.</td>
				</tr>
			</c:otherwise>
		</c:choose>
				<tr class="footer">
					<td colspan="2" class="pagination last" style="text-align:right"></td>
				</tr>
			</tbody>
		</table>
	</c:if>
	
	<c:if test="${ not canSeeRules }">
		Your permissions do not allow you to view rules for all of the apps attached to this WAF.
	</c:if>
	
	<c:if test="${ canSeeRules and hasApps }">
		<c:if test="${ canGenerateWafRules }">
			<spring:url value="/wafs/{wafId}/rules" var="generateRulesUrl">
				<spring:param name="wafId" value="${ waf.id }"/>
			</spring:url>
			<form:form method="post" action="${ fn:escapeXml(generateRulesUrl) }">
			<c:choose>
				<c:when test="${ empty waf.wafType.wafRuleDirectives and empty lastDirective}">
					No Directives Found.  
				</c:when>
				<c:otherwise>
					<select id="wafDirectiveSelect" name="wafDirective" >
						<option value="${ lastDirective.directive }"><c:out value="${ lastDirective.directive }"/></option>
						<c:forEach var="directive" items="${ directives }">
							<option value="${ directive.directive }"><c:out value="${ directive.directive }"/></option>
						</c:forEach>
					</select>
				</c:otherwise>
			</c:choose>
			<input class="btn btn-primary" id="generateWafRulesButton" type="submit" value="Generate WAF Rules" />
			</form:form>
		</c:if>
		
		<c:if test="${ not empty waf.wafRules }">
		<h3>WAF Rule Statistics (click to see details):</h3>
			<c:forEach var="wafRule" items="${ waf.wafRules }">
				<spring:url value="/wafs/{wafId}/rules/{wafRuleId}" var="generateRulesUrl">
					<spring:param name="wafId" value="${ waf.id }"/>
					<spring:param name="wafRuleId" value="${ wafRule.id }"/>
				</spring:url>
				<a href="${ fn:escapeXml(generateRulesUrl) }"> <c:out value="${ wafRule.nativeId }"/> - fired <c:out value="${fn:length(wafRule.securityEvents)}" /> times</a>
				<br/>
			</c:forEach>
		</c:if>
		
		<c:if test="${ not empty rulesText }">
			<h3>WAF Rules:</h3>
			<form id="form1" name="form1" method="post">
				<input class="btn btn-primary" id="downloadWafRulesButton" type="submit" value="Download Waf Rules"/>
			</form><br/>
			<div id="wafrule">
				<pre><c:out value="${ rulesText }"/></pre>	
			</div>
		</c:if>
	</c:if>
	
</body>