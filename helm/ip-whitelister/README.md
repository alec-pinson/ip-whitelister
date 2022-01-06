# IP Whitelister Helm Chart

1. Create your a Kubernetes secret containg `CLIENT_SECRET` and `REDIS_TOKEN`.
`ip-whitelister-secrets.yaml`
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ip-whitelister-secrets
type: Opaque
stringData:
  CLIENT_SECRET: notrealnotrealnotreal
  REDIS_TOKEN: my-sup3r-comp1ic4t3d-s3cr3t-t0k3n
```
2. Create your secret in Kubernetes  
```
kubectl apply -f ip-whitelister-secrets.yaml
```

3. Configure your `values.yaml`
```yaml
ingress:
  enabled: true
  className: ""
  annotations: {}
    # kubernetes.io/ingress.class: nginx
    # kubernetes.io/tls-acme: "true"
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: ImplementationSpecific

# env variables to be set within the container
env:
  - name: CONFIG_FILE
    value: "/app/config/config.yaml"

# env variables to be set within the container taken from a kubernetes secret
envFrom:
  - secretRef:
      name: ip-whitelister-secrets

# config
config: |
  url: https://<same-as-above-ingress-host>

  # User whitelistings will expire/be removed after 24 hours
  ttl: 24 # hours

  auth:
    type: azure
    tenant_id: notreal-not-real-not-notreal
    client_id: notreal-not-real-not-notreal

  redis:
    host: redis.host.com
    port: 6379

  resources:
    - cloud: azure
      type: frontdoor
      subscription_id: notreal-not-real-not-notreal
      resource_group: notreal-rg
      policy_name: notrealpolicy
    - cloud: azure
      type: storageaccount
      subscription_id: notreal-not-real-not-notreal
      resource_group: notreal-rg
      name: notrealstorage
      group:
        - b111111a-b11a-111a-bb11-1a111aaa11a11 # group object id
    - cloud: azure
      type: keyvault
      subscription_id: notreal-not-real-not-notreal
      resource_group: notreal-rg
      name: notrealkeyvault
    - cloud: azure
      type: postgres
      subscription_id: notreal-not-real-not-notreal
      resource_group: notreal-rg
      name: notpostgresserver
      ip_whitelist:
        - 51.0.0.0/24 # my company proxy addresses 3
      group:
        - a111111a-a11a-111a-aa11-1a111aaa11a11 # group object id

  # This whitelist will be applied to all resources and should be static non-human IPs only
  ip_whitelist:
    - 85.0.0.0/24 # my company proxy addresses 1
    - 200.0.0.0/24 # my company proxy addresses 2
```

4. Deploy to your Kubernetes cluster
```
helm upgrade ip-whitelister https://github.com/alec-pinson/ip-whitelister/releases/download/v1.0.4/helm-chart-ip-whitelister-0.3.0.tgz --install --wait -f values.yaml
```

