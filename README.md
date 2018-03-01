# Atomic scanner: scanner-analytics-integration


This is a container image scanner based on `atomic scan`. The goal of this
scanner is integration with [fabric8-analytics server]([200~https://github.com/fabric8-analytics/f8a-server-backbone/). 
The scanner reads the `Labels` of the image and triggers scan at server with data in Labels.

### Steps to use:

- Pull scanner Docker image from **registry.centos.org**:

```
$ docker pull registry.centos.org/pipeline-images/scanner-analytics-integration
```

- Install it using `atomic`:

```
$ atomic install registry.centos.org/pipeline-images/scanner-analytics-integration
```

- Run the scanner for a given image

```
$sudo IMAGE_NAME=<image-to-scan> SERVER=<server-url> atomic scan --scanner analytics-integration <image-to-scan>
```

where

```
IMAGE_NAME = Image under test
SERVER = Fabric7 Analytics Server URL
```

### Output of the scanner:

- Upon successful execution of scanner (irrespective of the successful server connection), scanner output looks like
```
# SERVER=http://localhost IMAGE_NAME=nshaikh/test_label atomic scan --verbose --scanner=analytics-integration nshaikh/test_label
docker run -t --rm -v /etc/localtime:/etc/localtime -v /run/atomic/2018-03-01-09-47-21-795242:/scanin -v /var/lib/atomic/analytics-integration/2018-03-01-09-47-21-795242:/scanout:rw,Z -v /var/run/docker.sock:/var/run/docker.sock -e IMAGE_NAME=nshaikh/test_label -e SERVER=http://localhost registry.centos.org/pipeline-images/scanner-analytics-integration python integration.py register

Scanner execution status: False

Files associated with this scan are in /var/lib/atomic/analytics-integration/2018-03-01-09-47-21-795242.
```

Notice line, `Scanner execution status: False` <- indicating the scanner could not connect to server.

Scanner exports the result as mentioned on stdout
```
Files associated with this scan are in /var/lib/atomic/analytics-integration/2018-03-01-09-47-21-795242.

```

Lets take a look at result

```
# tree /var/lib/atomic/analytics-integration/2018-03-01-09-47-21-795242
/var/lib/atomic/analytics-integration/2018-03-01-09-47-21-795242
├── aa295492a6702264ffe86c341e92aa83f9687e810cf29d72593eb7a2c27d0449
│   └── scanner-analytics-integration.json
└── environment.json

1 directory, 2 files
```

The result file is `scanner-analytics-integration.json`

Now lets take a look at the contents of result file.

```
# cat /var/lib/atomic/analytics-integration/2018-03-01-09-47-21-795242/aa295492a6702264ffe86c341e92aa83f9687e810cf29d72593eb7a2c27d0449/scanner-analytics-integration.json
{
    "Scan Type": "register",
    "CVE Feed Last Updated": "NA",
    "UUID": "a295492a6702264ffe86c341e92aa83f9687e810cf29d72593eb7a2c27d0449",
    "Scan Results": {
        "email-ids": "nshaikh@redhat.com,samuzzal@redhat.com",
        "git-sha": "46e443d",
        "git-url": "https://github.com/fabric8-analytics/f8a-server-backbone",
        "image_name": "nshaikh/test_label",
        "server_url": "http://localhost"
    },
    "Successful": false,
    "Finished Time": "2018-03-01-10-23-39-719301",
    "Summary": "Error: [\"Could not send POST request to URL https://localhost/register, with data: {'email-ids': u'nshaikh@redhat.com,samuzzal@redhat.com', 'git-sha': u'46e443d', 'git-url': u'https://github.com/fabric8-analytics/f8a-server-backbone'}.Error: ('Connection aborted.', error(111, 'Connection refused'))\", 'Could not send POST request to URL https://localhost/scanner-error, with data: {\\'email-ids\\': u\\'nshaikh@redhat.com,samuzzal@redhat.com\\', \\'image-name\\': \\'nshaikh/test_label\\', \\'error\\': [\"Could not send POST request to URL https://localhost/register, with data: {\\'email-ids\\': u\\'nshaikh@redhat.com,samuzzal@redhat.com\\', \\'git-sha\\': u\\'46e443d\\', \\'git-url\\': u\\'https://github.com/fabric8-analytics/f8a-server-backbone\\'}.Error: (\\'Connection aborted.\\', error(111, \\'Connection refused\\'))\"]}.Error: (\\'Connection aborted.\\', error(111, \\'Connection refused\\'))']",
    "Start Time": "2018-03-01-H-23-39",
    "Scanner": "scanner-analytics-integration"

```

The `"Scan Results"` field indicates, Labels data retrieved from image under test reports errors in `"Summary"` field.
Whether connection to server was successful, is indicated by `"Successful"` field,
here `false` as no server is running on `http://localhost` (given in scanner run command).


### What scanner does / behavior ?
 1. For a given image under test, retrieves labels as follow
    * git-url
    * git-sha
    * email-ids

 2. For a given `SERVER` URL, sends a `/register` POST REST API call with data as retrieved in 1.

 3. Upon failure with cases
    * failing to retrieve (or absence of) any of 3 the Labels in image under test
    * IMAGE_NAME env var not given in scanner command,

    sends a `/scanner-error` POST REST API call to server reporting errors with data as follow
    * image-image (if given, else "")
    * email-ids   (if given, else "")
    * errors      -  List of errors occured while running the scanner

 4. If `SERVER` URL is not given, scanner will record the errors in `"Summary"` field of local result file.
