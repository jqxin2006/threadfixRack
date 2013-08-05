<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Home</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/remote-pagination.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/teams_page.js"></script>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/jquery.form.js"></script>
</head>

<body id="apps">
	<h2>Applications</h2>

	<spring:url value="/organizations/teamTable" var="tableUrl"/>
	<div id="teamTable" data-url="<c:out value="${ tableUrl }"/>" style="margin-bottom:8px;margin-top:10px;">
		<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
			<a id="addTeamModalButton" href="#myTeamModal" role="button" class="btn" 
					data-toggle="modal">Add Team</a>
		</security:authorize>
	</div>
	
	<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
		<div id="myTeamModal" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
			<div id="formDiv">
				<%@ include file="/WEB-INF/views/organizations/newTeamForm.jsp" %>
			</div>
		</div>
	</security:authorize>
</body>
