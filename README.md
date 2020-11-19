# Exporter for expiration data of Kubernetes TLS secrets

Simple application for providing prometheus metrics on TLS secrets managed by cert-manager or annotated with "expiration-watcher/watch: true".

# Build it with
docker build -t ${REGISTRY}/expiration-watcher/expiration-watcher:latest .
docker push ${REGISTRY}/expiration-watcher/expiration-watcher:latest

# Deploy with
Alter the url towards your image

kubectl apply -f deployment/k8s.yml