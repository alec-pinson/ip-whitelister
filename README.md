# IP Whitelister

Login with AzureAD account and whitelist your IP against Cloud resources for 24 hours

1. User logs in
2. Their public IP is whitelisted for `24` hours

## Support

Currently only supports Azure resources:
- Azure FrontDoor

## Flow

1. User authenticates with AzureAD
2. Public IP is checked to make sure it is not part of the static `ipwhitelist`
3. Public IP is added to Redis database with ttl of `24` hours
4. Public IP is whitelisted against Cloud resources

## Requirements
- Service Principal account (authentication  + updating resources)
- Redis database (tracking user ip ttl)
