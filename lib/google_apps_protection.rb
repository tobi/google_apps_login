module GoogleAppsProtection
  
  Endpoint    = 'https://www.google.com/accounts/o8/site-xrds?hd=%s'
  AxEmail     = "http://axschema.org/contact/email"
  AxFirstName = 'http://axschema.org/namePerson/first'
  AxLastName  = 'http://axschema.org/namePerson/last'  
  
  DataRequest = {:required => [AxEmail, AxFirstName, AxLastName]}
  
  def authenticate_with_google_apps(domain)
    domain_endpoint = Endpoint % domain
    
    authenticate_with_open_id(domain_endpoint, DataRequest) do |result, identity_url, data|
      
      if result.successful?        
        
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
          true
        else
          login_failed(message)
          false
        end
      end      
    end
  end
  
  def login_successful
  end
  
  def login_failed(message = '')
    logger.warn("Login failed: #{message}")
    render :text => "Login failed: #{message}", :status => 500
  end
  
  
  protected :login_failed, :login_successful
  
end