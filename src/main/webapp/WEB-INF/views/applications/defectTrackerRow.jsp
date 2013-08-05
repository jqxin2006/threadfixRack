<%@ include file="/common/taglibs.jsp"%>

<td style="padding:5px;">Defect Tracker</td>
<c:choose>
	<c:when test="${ empty application.defectTracker }">
		<td style="padding:5px;" class="inputValue">
			<a id="addDefectTrackerButton" role="button" class="btn"
				<c:if test="${ !canManageApplications }"> data-has-no-manage-app-permisson="true" </c:if>
			>
				Add
			</a>
		</td>
	</c:when>
	<c:otherwise>
		<td style="padding:5px;" class="inputValue">
			<spring:url value="/configuration/defecttrackers/{defectTrackerId}" var="defectTrackerUrl">
				<spring:param name="defectTrackerId" value="${ application.defectTracker.id }"/>
			</spring:url>
			<a id="defectTrackerText" 
					<c:if test="${ addedDefectTracker }">
						data-added-tracker="true"
					</c:if>
					href="${ fn:escapeXml(defectTrackerUrl) }">
				<c:out value="${ application.defectTracker.name }"/>
			</a>
			<em>(<a href="<spring:url value="${ fn:escapeXml(application.defectTracker.url) }" />"><c:out value="${ fn:escapeXml(application.defectTracker.url) }"/></a>)</em>
		</td>
		<td style="padding:5px;">
			<a id="editDefectTrackerButton" role="button" class="btn" data-toggle="modal"
				<c:if test="${ !canManageApplications }"> data-has-no-manage-app-permisson="true" </c:if>				
			>				
				Edit
			</a>
		</td>
	</c:otherwise>
</c:choose>