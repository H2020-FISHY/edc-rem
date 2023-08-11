# Pod deployment on a Kubernetes Kind cluster

### Architecture:

The pod is made of 4 containers:

* [Security Capability Model](https://github.com/torsec/security-capability-model), (branch *stable*), listening on port 6000
* [Refinement engine](https://github.com/torsec/refinement-engine), (branch *pod*), listening on port 5000
* [NSF Catalogue](https://github.com/torsec/NSF-Catalogue), (branch *francesco*), listening on port 8984
* Remediator engine, this repository.

### Requirements:

- **kind**: https://github.com/kubernetes-sigs/kind
> kind is a tool for running local Kubernetes clusters using Docker container "nodes".
- **Docker**

INFO 🚧: even though this mini-guide is tailored for deploying the pod on a Kind Kuberentes cluster, you can run it just as well on any other Kubernetes cluster, such as those created with Minikube, or even native clusters.

---

![Polito-remediator](https://user-images.githubusercontent.com/5564178/214521033-d2677401-75e4-4ecc-bc3a-f63b8173803a.png)

---

# Deployment guide

### 0 - Clone the containers repositories into your machine

Make sure to select the correct branch for each project.

* Security Capability Model -> (branch *stable*)
* Refinement engine -> (branch *pod*)
* NSF Catalogue -> (branch *francesco*)

You'll find the k8s resources files in the *k8s_deployment* folder.

### 1 - Build Docker containers

The --platform flag is needed on *Apple Silicon Macs*.
*ARM* versions of the containers don't work because of some dependency missing *ARM* binaries.

```
docker build --platform linux/amd64 -t nsf-catalogue .
docker build --platform linux/amd64 -t secap .
docker build --platform linux/amd64 -t fishy-remediator .
docker build --platform linux/amd64 -t refeng .
```

#### Show images in Docker image registry

Check that the four images appear
```
docker image ls
```

### 2 - Create the Kubernetes *Kind* cluster

```
kind create cluster
```

### 3 - Load the Docker images in the Kind's cluster image registry

```
kind load docker-image fishy-remediator secap nsf-catalogue refeng
```

#### Show images in Kind cluster image registry

Check that the four images appear
```
docker exec -it kind-control-plane crictl images
```

### 4 - Spawn the pod

```
kubectl apply -f pod.yml
```
The shell from which you executed the command will automatically attach to the fishy-remediator container.

### 5 - Attach the terminal to the newly spawned pod.

In any moment you can exit from the shell session with the pod (i.e. the fishy-remediator container by default), and re-attach later via the following command:
```
kubectl attach -it poli-remediator
```

#### Local ports can be forwarded to Pod ones.

In this way container services are accessible directly on the machine in which the **Kind** cluster is running.
```
# kubectl port-forward <kubernetes-resource-name> <locahost-port>:<pod-port>
kubectl port-forward poli-remediator 6000:6000 # Security Capability Model
kubectl port-forward poli-remediator 5000:5000 # Refinement engine
kubectl port-forward poli-remediator 8984:8984 # NSF Catalogue
```
### 6 - Cleaning up

#### Delete the pod

```
kubectl delete pods poli-remediator
```

#### Delete the cluster

```
kind delete cluster
```
⚠️ If you delete a cluster and then want to deploy a the pod in a newly created cluster, you will need to reload the container images into the new cluster's image registry. To do that, you can follow this guide from step 2.
