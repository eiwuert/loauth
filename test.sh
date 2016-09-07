#!/bin/bash -x
HOST=localhost/loauth

TOKEN=`curl -X POST http://$HOST/password -H grant_type:password -H username:test -H password:test -H client_id:ponyponyponyswag -H client_secret:secret`
ACCESS=`echo $TOKEN | jq .access_token | sed 's/"//g'`
REFRESH=`echo $TOKEN | jq .refresh_token | sed 's/"//g'`
VERIFY=`curl http://$HOST/verify -H "Authorization: Bearer $ACCESS"`
echo $VERIFY
