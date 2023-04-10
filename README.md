# Building and Deploying

```
docker buildx build --push --tag brucewmac/keypair-caddy:dev .
docker pull brucewmac/keypair-caddy:dev
```

# Setup Kubernetes Cluster

```
kubectl apply -f kubernetes/service-account.yaml
kubectl apply -f kubernetes/secret.yaml
kubectl apply -f kubernetes/deployment.yaml
kubectl apply -f kubernetes/service.yaml
```
