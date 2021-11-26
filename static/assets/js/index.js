 $(function() {
 	'use strict'
 	$.plot('#flotChart', [{
 		data: dashData1,
 		color: '#3d0894',
 		bars: {
 			show: true,
 			lineWidth: 0,
 			barWidth: .5,
 			fill: 1
 		}
 	}, {
 		data: dashData4,
 		color: '#2d066d',
 		bars: {
 			show: true,
 			lineWidth: 0,
 			barWidth: .5,
 			fill: 1
 		}
 	}], {
 		series: {
 			shadowSize: 0
 		},
 		grid: {
 			borderWidth: 0,
 			labelMargin: 10
 		},
 		yaxis: {
 			show: true,
 			min: 0,
 			max: 45,
 			ticks: 4,
 			tickColor: 'rgba(255,255,255,.08)',
 			font: {
 				color: 'rgba(255,255,255,0)'
 			}
 		},
 		xaxis: {
 			show: true,
 			position: 'top',
 			tickColor: 'rgba(255,255,255,.08)',
 			font: {
 				color: 'rgba(255,255,255,.2)',
 				size: 11
 			}
 		}
 	});
	
	/* Activity */
	var options9 = {
		series: [60, 50, 35],
		chart: {
			height: 300,
			type: 'radialBar',
		},
		plotOptions: {
			radialBar: {
				dataLabels: {
					name: {
						fontSize: '22px',
					},
					value: {
						fontSize: '16px',
					},
					total: {
						show: false,
						label: 'Total',
						formatter: function(w) {
							return 249
						}
					}
				},
				track: {
					background: 'rgba(119, 119, 142, 0.2)',
				},
			}
		},
		labels: ['Sales', 'Visits', 'Profit'],
		colors: ['#5569f0', '#f55b39', '#2baf4a'],
	};
	var chart9 = new ApexCharts(document.querySelector("#activity"), options9);
	chart9.render();
	/* End Activity */
	
	
 	// animated smooth scroll on target from top menu
 	$('#mainDemoBtn').on('click', function(e) {
 		var target = $(this).attr('href');
 		$('html, body').animate({
 			scrollTop: $('' + target).offset().top
 		}, 500);
 		e.preventDefault();
 	});
 })