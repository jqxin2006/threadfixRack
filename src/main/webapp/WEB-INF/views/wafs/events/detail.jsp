<%@ include file="/common/taglibs.jsp"%>

<h2>Security Event Details</h2>

<spring:url value="/wafs/{wafId}/rules/{wafRuleId}" var="ruleUrl">
	<spring:param name="wafId" value="${ securityEvent.wafRule.waf.id }"/>
	<spring:param name="wafRuleId" value="${ securityEvent.wafRule.id }"/>
</spring:url>
<a id="viewSecEvents" href="${ fn:escapeXml(ruleUrl) }">Back to all Security Events for WafRule <c:out value="${ securityEvent.wafRule.nativeId }"/></a>

<h3>Snort Alert Information</h3>
<table>
	<tr>
		<td>Date:</td>
		<td><fmt:formatDate value="${securityEvent.importTime.time}" type="both" dateStyle="short" timeStyle="medium" /></td>
	</tr>
	<tr>
		<td>Type:</td>
		<td>${securityEvent.attackType}</td>
	</tr>
	<tr>
		<td>Rule ID:</td>
		<td>${securityEvent.wafRule.nativeId}</td>
	</tr>
	<tr>
		<td>Attacker IP</td>
		<td>${securityEvent.attackerIP}</td>
	</tr>
	<tr>
		<td>Full text:</td>
		<td>${securityEvent.logText}</td>
	</tr>
</table>
