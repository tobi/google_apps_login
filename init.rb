# Monkey patch openid with the google apps discovery patches
require 'vendor/gapps_openid'

# Add bundled ca-bundle to openid gem so that it starts validating HTTPS endpoints
OpenID.fetcher.ca_file = File.dirname(__FILE__) + '/lib/vendor/ca-bundle.crt'