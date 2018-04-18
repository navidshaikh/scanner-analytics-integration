FROM registry.centos.org/centos/centos:latest

LABEL INSTALL='docker run --rm --privileged -v /etc/atomic.d/:/host/etc/atomic.d/ $IMAGE sh /install.sh' \
      name='Analytics integration atomic scanner' \
      description='Atomic scanner for integration of container image scanning with fabri8-analytics server.' \
      git-sha='1a27cc4d3c038a37698ef9547e77f730600768bf' \
      email-ids='nshaikh@redhat.com' \
      git-url='https://github.com/navidshaikh/scanner-analytics-integration' \
      git-path='/' \
      target-file='Dockerfile'


# Install python-docker-py to spin up container using scan script
RUN yum -y update && \
    yum -y install epel-release && \
    yum -y install atomic python-docker-py && \
    yum clean all

ADD analytics-integration integration.py install.sh /
