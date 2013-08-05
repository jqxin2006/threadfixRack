var lastReportId = 1;
var lastFormatId = 1;

function reload(url) { 
	submitAjaxReport(url, '#reportForm', '#formDiv', '#successDiv', lastReportId, lastFormatId);
}

function selectReportType(url, reportId) {
	$(".sidebar").removeClass("sidebar-active");
	$(".sidebar-arrow").removeClass("sidebar-active");
	$(".sidebar" + reportId).addClass("sidebar-active");
	$("#arrow" + reportId).addClass("sidebar-active");
	
	submitAjaxReport(url, '#reportForm', '#formDiv', '#successDiv', reportId, 1);
}

function submitAjaxReport(url, formId, formDiv, successDiv, reportId, formatId) {
	
	lastReportId = reportId;
	lastFormatId = formatId;
	
	$("#connectionUnavailableMessage").css("display", "none");
	$(".toRemove").remove();
	
	var formData = $(formId).serializeArray();
	
	formData[formData.length] = { name: 'reportId', value: reportId };
	formData[formData.length] = { name: 'formatId', value: formatId };
	
	if (formatId == 1) {
		$.ajax({
			type : "POST",
			url : url,
			data : formData,
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$(formDiv).html(text);
				} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
					$(successDiv).html(text);
					if ($("#reportDiv").attr("data-show-csv-export")) {
						$("#csvLink").css("display","");
					} else{
						$("#csvLink").css("display","none");
					}
					if ($("#reportDiv").attr("data-show-pdf-export")) {
						$("#pdfLink").css("display","");
					} else{
						$("#pdfLink").css("display","none");
					}
				} else {
					try {
						var json = $.parseJSON($.trim(text));
						if (json.isJSONRedirect) {
							window.location.href = json.redirectURL;
						}
					} catch (e) {
						$("#connectionUnavailableMessage").css("display", "");
					}
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				$("#connectionUnavailableMessage").css("display", "");
		    }
		});
	} else {
		var input1 = $("<input>").attr("type", "hidden").attr("name", "formatId").addClass('toRemove').val(formatId);
		var input2 = $("<input>").attr("type", "hidden").attr("name", "reportId").addClass('toRemove').val(reportId);
		$(formId).append($(input1));
		$(formId).append($(input2));
		$(formId).submit();
	}
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

addToDocumentReadyFunctions(function() {
	var orgSelect = $("#orgSelect");
	var appSelect = $("#appSelect");

	if (!$("#successDiv").attr("data-hide-reports")) {
		orgSelect.on("change", function() { reload(orgSelect.attr("data-refresh-url")); });
		appSelect.on("change", function() { reload(orgSelect.attr("data-refresh-url")); });
	
		var hideSelects = function() {
			$(".reportTypeSelect").each(function(){
				$(this).css("display","none");
			});
		};
		
		$(".reportTypeListSelector").on("click", function() {
			hideSelects();
			var select = $("#" + $(this).attr("data-report-list"));
			select.css("display","");
			var selectedReport = select.children(":selected");
			selectReportType(selectedReport.attr("data-url"), selectedReport.attr("data-report-id"));
		});
		
		$(".reportTypeSelect").on("change", function() {
			var selectedReport = $(this).children(":selected");
			selectReportType(selectedReport.attr("data-url"), selectedReport.attr("data-report-id"));
		});
		
		if ($("#appSelect").attr("data-first-app-id")) {
			$("#appSelect").val($("#appSelect").attr("data-first-app-id"));
		}
	
		if ($("#successDiv").attr('data-first-report') !== "") {
			var targetOption = $("option[data-report-id=" + $("#successDiv").attr('data-first-report') + "]");
			hideSelects();
			targetOption.closest("select").css("display","");
			$(".reportTypeListSelector").closest("li").removeClass("active");
			targetOption.prop("selected", true);
			targetOption.closest("select").val(targetOption.val());
			$("#" + targetOption.closest("select").attr("data-tab")).closest("li").click();
			$("#" + targetOption.closest("select").attr("data-tab")).closest("li").addClass("active");
			selectReportType(targetOption.attr("data-url"), targetOption.attr("data-report-id"));
		} else {
			$(".reportTypeListSelector").each(function() {
				if ($(this).closest("li").attr("class").indexOf("active") != -1) {
					$(this).click();
				}
			});
		}
		
		$(".reportDownload").on("click", function() {
			submitAjaxReport($(this).attr("data-url"), '#reportForm', '#formDiv', '#successDiv', $("#reportDiv").attr("data-report-id"), $(this).attr("data-format-id"));
		});
		
	} else {
		orgSelect.attr("disabled","disabled");
		appSelect.attr("disabled","disabled");
	}
});

