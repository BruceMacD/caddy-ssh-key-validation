# Building and Deploying

```
docker buildx build --push --build-arg CACHEBUST=$(date +%s) --tag brucewmac/keypair-caddy:dev .
docker pull brucewmac/keypair-caddy:dev
```

# Setup Kubernetes Cluster

Create cluster role bindings for your expected users.
Update `kubernetes/mapping.yaml` to map these users to their corresponding public SSH keys.

```
kubectl apply -f kubernetes/mapping.yaml
kubectl apply -f kubernetes/service-account.yaml
kubectl apply -f kubernetes/secret.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
```

# Getting Certificate Authority Data

Caddy automatically generates a certificate. You'll need to retrieve it set it in your Kubernetes configuration file.

```
$ kubectl get pods -l app=keypair-agent

$ kubectl cp <pod_name>:data/caddy/certificates/local/localhost/localhost.crt localhost.crt

$ base64 -i localhost.crt
# add this value to your Kubernetes config
```
