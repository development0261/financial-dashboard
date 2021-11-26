(function($) {
	"use strict";
	
	// ______________Active Class
	$(".app-sidebar li  a").each(function() {
	  var pageUrl = window.location.href.split(/[?#]/)[0];
		if (this.href == pageUrl) { 
			$(this).addClass("active");
			$(this).parent().addClass("active"); // add active to li of the current link
			$(this).parent().parent().prev().addClass("active"); // add active class to an anchor
			$(this).parent().parent().prev().click(); // click the item to make it drop
		}
	});
	
	//Active Class
	$(".app-sidebar li a").each(function() {
		var pageUrl = window.location.href.split(/[?#]/)[0];
		if (this.href == pageUrl) {
			$(this).addClass("active");
			$(this).parent().addClass("active"); // add active to li of the current link
			$(this).parent().addClass("resp-tab-content-active"); // add active to li of the current link
			$(this).parent().parent().parent().prev().addClass("active"); // add active class to an anchor
			$(this).parent().parent().parent().prev().click(); // click the item to make it drop
		}
	});
	
	$(".submenu-list li a").each(function() {
		var pageUrl = window.location.href.split(/[?#]/)[0];
		if (this.href == pageUrl) {
			$(this).addClass("active");
			$(this).parent().parent().parent().parent().parent().addClass("active"); // add active to li of the current link
			$(this).parent().parent().parent().parent().parent().addClass("resp-tab-content-active"); // add active to li of the current link
			$(this).parent().parent().parent().prev().addClass("active"); // add active class to an anchor
			$(this).parent().parent().parent().prev().click(); // click the item to make it drop
		}
	});
	
	$(document).ready(function(){		
		
		if ($('.dashboard-xino.active').hasClass('active'))
        $('li.dashboard-xino').addClass('active');
	
	    if ($('.widget-xino.active').hasClass('active'))
        $('li.widget-xino').addClass('active');
	
        if ($('.mail-xino.active').hasClass('active'))
        $('li.mail-xino').addClass('active');
	
		if ($('.app-xino.active').hasClass('active'))
        $('li.app-xino').addClass('active');
	
		if ($('.icons-xino.active').hasClass('active'))
        $('li.icons-xino').addClass('active');
	
		if ($('.maps-xino.active').hasClass('active'))
        $('li.maps-xino').addClass('active');
		
		if ($('.tables-xino.active').hasClass('active'))
        $('li.tables-xino').addClass('active');
	
		if ($('.element-xino.active').hasClass('active'))
        $('li.element-xino').addClass('active');
	
		if ($('.advanced-xino.active').hasClass('active'))
        $('li.advanced-xino').addClass('active');
	
		if ($('.forms-xino.active').hasClass('active'))
        $('li.forms-xino').addClass('active');
	
		if ($('.chart-xino.active').hasClass('active'))
        $('li.chart-xino').addClass('active');
		
		if ($('.pages-xino.active').hasClass('active'))
        $('li.pages-xino').addClass('active');
		
		if ($('.ecommerce-xino.active').hasClass('active'))
        $('li.ecommerce-xino').addClass('active');
	
		if ($('.utilities-xino.active').hasClass('active'))
        $('li.utilities-xino').addClass('active');
	
		if ($('.custom-xino.active').hasClass('active'))
        $('li.custom-xino').addClass('active');
	
		if ($('.submenus-xino.active').hasClass('active'))
        $('li.submenus-xino').addClass('active');
	
	});
	
	
	// VerticalTab
	$('#sidemenu-Tab').easyResponsiveTabs({
		type: 'vertical',
		width: 'auto', 
		fit: true, 
		closed: 'accordion',
		tabidentify: 'hor_1',
		activate: function(event) {
			var $tab = $(this);
			var $info = $('#nested-tabInfo2');
			var $name = $('span', $info);
			$name.text($tab.text());
			$info.show();
		}
	});
	
	const ps11 = new PerfectScrollbar('.first-sidemenu', {
	  useBothWheelAxes:true,
	  suppressScrollX:true,
	});
	const ps12 = new PerfectScrollbar('.second-sidemenu', {
	  useBothWheelAxes:true,
	  suppressScrollX:true,
	});
	
})(jQuery);