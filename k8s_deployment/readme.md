Alternatively you can use a k8s **Service** resource to access the various container ports directly through the k8s node.
In this way you won't need to keep the *kubectl port-forward* commands running in the Terminal to expose the desired ports.

This is the command to deploy both the pod and the **NodePort Service** resource:

```
kubectl apply -f pod_and_service.yml
```

If you are using Docker engine directly on Linux 
you can then access the services by connecting to the node IP which you can find with the following command:

```
kubectl get nodes -o wide
```

Otherwise if you're using **Docker Desktop** (on Linux/macOS/Windows) which runs containers inside a Linux VM, you can access the ports through localhost by adding port mappings at cluster creation time. With port mappings you will forward the desired ports from the host to the k8s internal node ports:
Port mappings must be passed through the config.yml file, which you can find in this folder, when you create the cluster.


This is the command you can use to create the cluster with a custom config file in which port mappings are declared:

```
kind create cluster --config=config.yml
```

