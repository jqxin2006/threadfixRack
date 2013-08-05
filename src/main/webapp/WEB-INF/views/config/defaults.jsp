<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Configure Defaults</title>
</head>

<body id="config">
	<h2>Configure Defaults</h2>
	
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	
	<spring:url value="" var="emptyUrl"></spring:url>
	<form:form modelAttribute="defaultConfiguration" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tr>
				<td>Global Group enabled for new users?</td>
				<td class="inputValue" style="text-align: left;">
					<form:checkbox id="globalGroupEnabledCheckbox" path="globalGroupEnabled" />
				</td>
				<td class="inputValue">
					<form:select id="roleSelect" path="defaultRoleId">
						<form:option value="0" label="Select a role" />
						<form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
					</form:select>
				</td>
				<td style="border: 0px solid black; background-color: white; padding-left: 5px">
					<form:errors id="globalGroupEnabledErrors" path="globalGroupEnabled" cssClass="errors" />
				</td>
			</tr>
		</table>
		<br/>
		<button class="btn btn-primary" type="submit" id="updateDefaultsButton">Update Defaults</button>
	</form:form>
</body>
