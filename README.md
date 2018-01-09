Atomic scanner: scanner-analytics-integration
---------------------------------------------

This is a container image scanner based on `atomic scan`. The goal of this
scanner is integration with fabric8-analytics server. The scanner accumulate
container application related information.

Steps to use:

- Pull Docker image from **registry.centos.org**:

```
$ docker pull registry.centos.org/pipeline-images/scanner-analytics-integration
```

- Install it using `atomic`:

```
$ atomic install registry.centos.org/pipeline-images/scanner-analytics-integration
```

- Mount the image's rootfs because by default `atomic scan` would mount it in
  read-only mode but we need read-write capability:

```
$ sudo atomic scan --scanner analytics-integration <image-to-scan>
```
