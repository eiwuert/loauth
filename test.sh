#!/bin/bash -x

TOKEN=`curl -X POST http://localhost:8000/password -H grant_type:password -H username:user -H password:pass -H client_id:10 -H client_secret:secret`
ACCESS=`echo $TOKEN | jq .access_token | sed 's/"//g'`
REFRESH=`echo $TOKEN | jq .refresh_token | sed 's/"//g'`
VERIFY=`curl http://localhost:8000/verify -H "Authorization: Bearer $ACCESS"`
echo $VERIFY
