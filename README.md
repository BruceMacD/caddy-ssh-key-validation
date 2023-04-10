# Building and Deploying

```
docker buildx build --push --tag brucewmac/keypair-caddy:dev .
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
