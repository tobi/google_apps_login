Google Apps Login:
------------------

This plugin allows you to use your Google Apps for Domains accounts to protect areas of your 
web apps such as internal admin areas. Great if your company or group is already using Google
Apps. This may require a premium account. 

Requirements:
-------------
  
  * pelle-ruby-openid (2.1.8) ( not sure if normal ruby-openid works, it's slightly out of date)
  * pelle's fork of openid_id_authentication plugin ( http://github.com/pelle/open_id_authentication )

Example usage:
--------------

  class SecretController < ApplicationController  
    before_filter :google_login_required
  
    def index
      render :text => "Hey #{session[:admin][:email]}"
    end
  
    protected 
  
    def google_login_required
      return if session[:admin]
    
      authenticate_with_google_apps "shopify.com" do |profile|
        session[:admin] = profile
      end
    end
  
  end


Profile contains first_name, last_name, identity_url and email. 