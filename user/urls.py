from django.contrib import admin
from django.urls import path, include
from .views import *
urlpatterns = [
    path('signup', signup, name='signup'),
    path('loginProcess', loginProcess, name='loginProcess'),
    path('logoutProcess', logoutProcess, name='logoutProcess'),
    path('dashboard', dashboard, name='dashboard'),
    path('updatepassword', updatepassword, name='updatepassword'),
    path('forgetpassword', forgetpassword, name='forgetpassword'),
    path('confirmforgotPassword/<uidb64>/<token>/',confirmforgotPassword,name="confirmforgotPassword"),
    path('confirmforgotPasswordForm',confirmforgotPasswordForm,name="confirmforgotPasswordForm"),
    path('btc_data/',get_latest_btc),
    path('eth_data/',get_latest_eth),
    path('iot_data/',get_latest_iot),
    path('rep_data/',get_latest_rep),
    path('bts_data/',get_latest_bts),
    path('dash_data/',get_latest_dash),
    path('eur_data/',get_latest_eur),
    path('ltc_data/',get_latest_ltc),
    path('xmr_data/',get_latest_xmr),
    path('neo_data/',get_latest_neo),
    path('all_data/<str:crypto>/<str:date>/<str:time>/',crypto_all_data),
    path('history/<str:crypto>',crypto_history),
    path('history_data/<str:crypto>',crypto_history_data),
    path('avg_price/<str:crypto>',average_price),
    # path("all_data_filter/<str:date>/<str:time>/",all_data_filter,name="all_data_filter"),
    # Stocks API stocks_data
    path('stocks_data/<str:stock>/<str:time>/', stocks_data),
    
    path('demo', demo, name='demo'),
    path('companyData/<str:stock>/',companyData,name="companyData"),
    path('get_graphData/<str:crypto>/',get_graphData,name="get_graphData"),
    path('get_allgraphData/<str:crypto>/',get_allgraphData,name="get_allgraphData"),

    path('get_graphDataTime/<str:crypto>/<str:time>/',get_graphDataTime,name="get_graphDataTime"),
    path('week_up_down/<str:stock>/',week_up_down,name="week_up_down"),
    path('week_up_down_for_crypto/<str:crypto>/',week_up_down_for_crypto,name="week_up_down_for_crypto"),

]