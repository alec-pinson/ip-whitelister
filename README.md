# IP Whitelister

Login with AzureAD account and whitelist your IP against Cloud resources for 24 hours

## Flow

1. User authenticates with AzureAD
2. Public IP is checked to make sure it is not part of the static `ipwhitelist`
3. Public IP is added to Redis database with ttl of `24` hours
4. Public IP is whitelisted against Cloud resources

## Requirements
- Service Principal account (authentication  + updating resources)
- Redis database (tracking user ip ttl)

## Cloud/Resource Support

**Azure:**
- Azure FrontDoor

## Docker Image
https://hub.docker.com/r/alecpinson/ip-whitelister

## Usage

### Docker Compose
1. Configure a config file see `config/config.yaml`
2. Check/reconfigure `docker-compose.yaml`
3. Run `docker-compose up -d`

### Helm
See [README](helm/ip-whitelister/README.md)
