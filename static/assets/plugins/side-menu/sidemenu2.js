(function () {
	"use strict";

	var slideMenu = $('.side-menu');
	$('.app').addClass('sidenav-toggled');

	// Toggle Sidebar
	$(document).on('click','[data-toggle="sidebar"]',function(event) {
		event.preventDefault();
		$('.app').toggleClass('sidenav-toggled');
		   $('.app').removeClass('sidenav-toggled1');
	});

	$(document).on("click", ".sidenav-toggled .app-sidebar", function() {
        $('.app').addClass('sidenav-toggled1');
    });
	
	$(document).on("click", ".sidenav-toggled.sidenav-toggled1 .app-content", function() {
       $('.app').removeClass('sidenav-toggled1');
    });
	

	if ( $(window).width() > 739) {     
		$('.app').ready(function(event) {
			$('.app').removeClass('sidenav-toggled1');
		});
	} 

	//Mobile menu 
	jQuery(document).ready(function($) {
	  var alterClass = function() {
		var ww = document.body.clientWidth;
		if (ww < 739) {
		  $('body').removeClass('sidenav-toggled');
		} else if (ww >= 738) {
		  $('body').addClass('sidenav-toggled');
		};
	  };
	  $(window).resize(function(){
		alterClass();
	  });
	  //Fire it when the page first loads:
	  alterClass();
	});
	


	// Activate sidebar slide toggle
	$("[data-toggle='slide']").on('click', function(e) {
		var $this = $(this);
		var checkElement = $this.next();
		var animationSpeed = 300,
		slideMenuSelector = '.slide-menu';
		if (checkElement.is(slideMenuSelector) && checkElement.is(':visible')) {
		  checkElement.slideUp(animationSpeed, function() {
			checkElement.removeClass('open');
		  });
		  checkElement.parent("li").removeClass("is-expanded");
		}
		 else if ((checkElement.is(slideMenuSelector)) && (!checkElement.is(':visible'))) {
		  var parent = $this.parents('ul').first();
		  var ul = parent.find('ul:visible').slideUp(animationSpeed);
		  ul.removeClass('open');
		  var parent_li = $this.parent("li");
		  checkElement.slideDown(animationSpeed, function() {
			checkElement.addClass('open');
			parent.find('li.is-expanded').removeClass('is-expanded');
			parent_li.addClass('is-expanded');
		  });
		}
		if (checkElement.is(slideMenuSelector)) {
		  e.preventDefault();
		}
	});
	
	// Activate sidebar slide toggle
	$("[data-toggle='sub-slide']").on('click', function(e) {
		var $this = $(this);
		var checkElement = $this.next();
		var animationSpeed = 300,
		slideMenuSelector = '.sub-slide-menu';
		if (checkElement.is(slideMenuSelector) && checkElement.is(':visible')) {
		  checkElement.slideUp(animationSpeed, function() {
			checkElement.removeClass('open');
		  });
		  checkElement.parent("li").removeClass("is-expanded");
		}
		 else if ((checkElement.is(slideMenuSelector)) && (!checkElement.is(':visible'))) {
		  var parent = $this.parents('ul').first();
		  var ul = parent.find('ul:visible').slideUp(animationSpeed);
		  ul.removeClass('open');
		  var parent_li = $this.parent("li");
		  checkElement.slideDown(animationSpeed, function() {
			checkElement.addClass('open');
			parent.find('li.is-expanded').removeClass('is-expanded');
			parent_li.addClass('is-expanded');
		  });
		}
		if (checkElement.is(slideMenuSelector)) {
		  e.preventDefault();
		}
	});
	
	


	//Activate bootstrip tooltips
	$("[data-toggle='tooltip']").tooltip();
	
	
	// ______________Active Class
	$(".app-sidebar a").each(function() {
	  var pageUrl = window.location.href.split(/[?#]/)[0];
		if (this.href == pageUrl) { 
				$(this).addClass("active");
				$(this).parent().addClass("is-expanded");
				$(this).parent().parent().prev().addClass("active"); 
				$(this).parent().parent().addClass("open"); 
				$(this).parent().parent().prev().addClass("is-expanded"); 
				$(this).parent().parent().parent().addClass("is-expanded"); 
				$(this).parent().parent().parent().parent().addClass("open"); 
				$(this).parent().parent().parent().parent().prev().addClass("active"); 
				$(this).parent().parent().parent().parent().parent().addClass("is-expanded"); 
			}
	});
	
	var toggleSidebar = function() {
		var w = $(window);
		if(w.outerWidth() <= 1024) {
			$("body").addClass("sidebar-gone");
			$(document).off("click", "body").on("click", "body", function(e) {
				if($(e.target).hasClass('sidebar-show') || $(e.target).hasClass('search-show')) {
					$("body").removeClass("sidebar-show");
					$("body").addClass("sidebar-gone");
					$("body").removeClass("search-show");
				}
			});
		}else{
			$("body").removeClass("sidebar-gone");
		}
	}
	toggleSidebar();
	$(window).resize(toggleSidebar);
	
	//p-scroll
	const ps1 = new PerfectScrollbar('.sidebar-scroll', {
		suppressScrollX: true
		});
		
		
	
	//sticky-header
		$(window).on("scroll", function(e){
		if ($(window).scrollTop() >= 70) {
			$('.main-header').addClass('fixed-header');
			$('.main-header').addClass('visible-title');
		}
		else {
			$('.main-header').removeClass('fixed-header');
			$('.main-header').removeClass('visible-title');
		}
    });

})();