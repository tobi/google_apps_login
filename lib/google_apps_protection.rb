module GoogleAppsProtection
  
  Endpoint    = 'https://www.google.com/accounts/o8/site-xrds?hd=%s'
  AxEmail     = "http://axschema.org/contact/email"
  AxFirstName = 'http://axschema.org/namePerson/first'
  AxLastName  = 'http://axschema.org/namePerson/last'  
  
  DataRequest = {:required => [AxEmail, AxFirstName, AxLastName]}
  
  def authenticate_with_google_apps(domain)
    domain_endpoint = Endpoint % domain
    
    authenticate_with_open_id(domain_endpoint, DataRequest) do |result, identity_url, data|
            
      case result.status
      when :missing
        login_failed "Sorry, the OpenID server couldn't be found"
      when :invalid
        login_failed "Sorry, but this does not appear to be a valid OpenID"
      when :canceled
        login_failed "OpenID verification was canceled"
      when :failed
        login_failed "Sorry, the OpenID verification failed"
      when :successful
                
        profile = {
          :identity_url => identity_url,
          :email        => data[AxEmail].first,
          :first_name   => data[AxFirstName].first,
          :last_name    => data[AxLastName].first
        }
        
        email_domain = profile[:email].split("@").last rescue nil
        
        if email_domain != domain
          login_failed("Domain #{profile[:email].split("@").inspect} is not allowed here")
          return 
        end
        
        if yield(profile)
          login_successful
          true
        else
          login_failed(message)
          false
        end          
      else
        login_failed "Unknown OpenID error: #{result.status}"      
      end
    end
  end
  
  def login_successful
    logger.info("Login successful")
  end
  
  def login_failed(message = '')
    logger.warn("Login failed: #{message}")
    render :text => "Login failed: #{message}", :status => 500
  end
  
  
  protected :login_failed, :login_successful, :authenticate_with_google_apps
  
end