## User Information

- METHOD: GET
- OPENAPI URL: `/openapi/uinfo`
- PARAMETERS:
```
Parameter name | Type       | Mandatory | Description                                              
---------------+------------+-----------+----------------------------------------------------------
access_tokens  | URL/string | yes       | [OPEN API] The access_token obtained by the application  
               |            |           | after authorization                                      
```

## Quota Information

- METHOD: GET
- APP API URL: `/api/quota`
- OPENAPI URL: `/openapi/quota`
- PARAMETERS:
```
Parameter name | Type       | Mandatory | Description                                              
---------------+------------+-----------+----------------------------------------------------------
access_tokens  | URL/string | yes       | [OPEN API] The access_token obtained by the application  
               |            |           | after authorization                                      
---------------+------------+-----------+----------------------------------------------------------
checkfree      | URL/int    | no        | Specifies whether to check for free space:               
               |            |           | 0 = disabled (default), 1 = enabled                      
---------------+------------+-----------+----------------------------------------------------------
checkexpire    | URL/int    | no        | Specifies whether to check for expired space:            
               |            |           | 0 = disabled (default), 1 = enabled                      
```