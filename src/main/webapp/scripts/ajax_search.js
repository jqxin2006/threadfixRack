//TODO optimize this file
var current;
var previous;
var len;

function disableEnterKey(e)
{
     var key;     
     if(window.event)
          key = window.event.keyCode; //IE
     else if(e)
          key = e.which; //firefox 
     return (key != 13);
}

function searchCweSuggest(e) {
    var key;
    if (window.event) {
         key = window.event.keyCode; //IE
	} else if (e) {
         key = e.which; //firefox
	} 
    
    if (key == 13) {
    	//Enter key
    	setCweSearch(document.getElementById('search_cwe_suggest').childNodes[current].innerHTML);
    	e.cancel = true;
    } else if (key == 38) {
		// Up key
		previous = (current + len)%len;
		current = (current - 1 + len)%len;
		var div_value = document.getElementById('search_cwe_suggest').childNodes[current];
		var div_value2 = document.getElementById('search_cwe_suggest').childNodes[previous];
		div_value.className = 'suggest_link_over';
		div_value2.className = 'suggest_link';
		$('#txtSearch').val(div_value.innerHTML);
		e.cancel = true;
	} else if (key == 40) {
		// Down key
		previous = (current + len)%len;
		current = (current + 1)%len;
		var div_value = document.getElementById('search_cwe_suggest').childNodes[current];
		var div_value2 = document.getElementById('search_cwe_suggest').childNodes[previous];
		div_value.className = 'suggest_link_over';
		div_value2.className = 'suggest_link';
		$('#txtSearch').val(div_value.innerHTML);
		e.cancal = true;
	}else{
		var str = escape($("#txtSearch").val());
		var urlString = $("#url1").val();
		if (str) {
			$.ajax({
				type : "POST",
				url : urlString,
				data : "prefix=" + str,
				success : function(text) {
					showCweResponse(text);
				}
			});
		} else {
			$("#search_cwe_suggest").html('');
			$('#search_cwe_suggest').css('visibility', 'hidden');
		}
	}
}

function searchUrlStaticSuggest(e) {
    var key;
    var suggest = document.getElementById("search_url_static_suggest");
    if (window.event) {
        key = window.event.keyCode; //IE
	} else if (e) {
        key = e.which; //firefox
	} 
   
    if (key == 13) {
    	setUrlStaticSearch(suggest.childNodes[current].innerHTML);
    	e.cancel = true;
    } else if (key == 38) {
		// Up key
		previous = (current + len)%len;
		current = (current - 1 + len)%len;
		var div_value = suggest.childNodes[current];
		var div_value2 = suggest.childNodes[previous];
		div_value.className = 'suggest_link_over';
		div_value2.className = 'suggest_link';
		$('#urlStaticSearch').val(div_value.innerHTML);
		e.cancel = true;
	} else if (key == 40) {
		// Down key
		previous = (current + len)%len;
		current = (current + 1)%len;
		var div_value = suggest.childNodes[current];
		var div_value2 = suggest.childNodes[previous];
		div_value.className = 'suggest_link_over';
		div_value2.className = 'suggest_link';
		$('#urlStaticSearch').val(div_value.innerHTML);
		e.cancal = true;
	}else{
		var str = escape($("#urlStaticSearch").val());
		var urlString = $("#url2").val();
		if (str) {
			$.ajax({
				type : "POST",
				url : urlString,
				data : "hint=" + str,
				success : function(text) {
					showUrlStaticResponse(text);
				}
			});
		} else {
			$("#search_url_suggest").html('');
			$('#search_cwe_suggest').css('visibility', 'hidden');
		}
	}
}

function searchUrlDynamicSuggest(e) {
    var key;
    var suggest = document.getElementById("search_url_dynamic_suggest");
    if (window.event) {
        key = window.event.keyCode; //IE
	} else if (e) {
        key = e.which; //firefox
	} 
   
   if (key == 13) {
    	setUrlDynamicSearch(suggest.childNodes[current].innerHTML);
    	e.cancel = true;
    } else if (key == 38) {
		// Up key
		previous = (current + len)%len;
		current = (current - 1 + len)%len;
		var div_value = suggest.childNodes[current];
		var div_value2 = suggest.childNodes[previous];
		div_value.className = 'suggest_link_over';
		div_value2.className = 'suggest_link';
		$('#urlDynamicSearch').val(div_value.innerHTML);
		e.cancel = true;
	} else if (key == 40) {
		// Down key
		previous = (current + len)%len;
		current = (current + 1)%len;
		var div_value = suggest.childNodes[current];
		var div_value2 = suggest.childNodes[previous];
		div_value.className = 'suggest_link_over';
		div_value2.className = 'suggest_link';
		$('#urlDynamicSearch').val(div_value.innerHTML);
		e.cancal = true;
	}else{
		var str = escape($("#urlDynamicSearch").val());
		var urlString = $("#url2").val();
		if (str) {
			$.ajax({
				type : "POST",
				url : urlString,
				data : "hint=" + str,
				success : function(text) {
					showUrlDynamicResponse(text);
				}
			});
		} else {
			$("#search_url_suggest").html('');
			$('#search_cwe_suggest').css('visibility', 'hidden');
		}
	}
}

showCweResponse = function(text) {
	var ss = $("#search_cwe_suggest");
	ss.html('');
	current = -1;
	var str = text.split("\n");
	len = str.length - 1 < 10 ? str.length - 1 : 10;
	for (i = 0; i < len; i++) {
		var suggest = '<div onmouseover="javascript:suggestOver(this);" ';
		suggest += 'onmouseout="javascript:suggestOut(this);" ';
		suggest += 'onclick="javascript:setCweSearch(this.innerHTML);" ';
		suggest += 'class="suggest_link">' + str[i] + '</div>';
		ss.html(ss.html() + suggest);
	}
	
	if (! Boolean(text)) {
		$('#search_cwe_suggest').css('visibility', 'hidden');
	} else {
		$('#search_cwe_suggest').css('visibility', 'visible');
	}
};

showUrlStaticResponse = function(text) {
	var ss = $("#search_url_static_suggest");
	ss.html('');
	current = -1;
	var str = text.split("\n");
	len = str.length - 1 < 10 ? str.length - 1 : 10;
	for (i = 0; i < len; i++) {
		var suggest = '<div onmouseover="javascript:suggestOver(this);" ';
		suggest += 'onmouseout="javascript:suggestOut(this);" ';
		suggest += 'onclick="javascript:setUrlStaticSearch(this.innerHTML);" ';
		suggest += 'class="suggest_link">' + str[i] + '</div>';
		ss.html(ss.html() + suggest);
	}

	if (! Boolean(text)) {
		$('#search_url_static_suggest').css('visibility', 'hidden');
	} else {
		$('#search_url_static_suggest').css('visibility', 'visible');
	}
};

showUrlDynamicResponse = function(text) {
	var ss = $("#search_url_dynamic_suggest");
	ss.html('');
	current = -1;
	var str = text.split("\n");
	len = str.length - 1 < 10 ? str.length - 1 : 10;
	for (i = 0; i < len; i++) {
		var suggest = '<div onmouseover="javascript:suggestOver(this);" ';
		suggest += 'onmouseout="javascript:suggestOut(this);" ';
		suggest += 'onclick="javascript:setUrlDynamicSearch(this.innerHTML);" ';
		suggest += 'class="suggest_link">' + str[i] + '</div>';
		ss.html(ss.html() + suggest);
	}
	
	if (! Boolean(text)) {
		$('#search_url_dynamic_suggest').css('visibility', 'hidden');
	} else {
		$('#search_url_dynamic_suggest').css('visibility', 'visible');
	}
};

function suggestOver(div_value) {
	div_value.className = 'suggest_link_over';
}
function suggestOut(div_value) {
	div_value.className = 'suggest_link';
}

function setCweSearch(value) {
	$('#txtSearch').val(value);
	$('#search_cwe_suggest').css('visibility', 'hidden');
	$('#search_cwe_suggest').html('');
}

function setUrlStaticSearch(value) {
	$('#urlStaticSearch').val(value);
	$('#search_url_static_suggest').css('visibility', 'hidden');
	$('#search_url_static_suggest').html('');
}

function setUrlDynamicSearch(value) {
	$('#urlDynamicSearch').val(value);
	$('#search_url_dynamic_suggest').css('visibility', 'hidden');
	$('#search_url_dynamic_suggest').html('');
}