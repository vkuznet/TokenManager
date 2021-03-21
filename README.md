# Token manager

[![Build Status](https://travis-ci.org/vkuznet/TokenManager.svg?branch=master)](https://travis-ci.org/vkuznet/TokenManager)
[![Go Report Card](https://goreportcard.com/badge/github.com/vkuznet/TokenManager)](https://goreportcard.com/report/github.com/vkuznet/TokenManager)

This is a simple tool to handle CERN SSO tokens.
```
# build token manager
make

# obtain valid TOKEN from web interface by visiting http://YOUR_URL/token
# it will return the following structure
AccessToken: <token>
AccessExpire: 120
RefreshToken: <token>
RefreshExpire: 120

# use refresh token to proceed

# run token manager with given URL and valid TOKEN
# it will obtain new token at given interval and write it out
# to given file (/tmp/access.token). The written token will be the access token
# which you can use for further access
./token -interval 600 -out /tmp/access.token -url <URL> -token <refresh.token>
```
