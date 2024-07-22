# contained: A simple Docker service for running files in a container

`contained` is an HTTP service presenting a single endpoint that allows
a user to upload a set of files and run them in a Docker container,
capturing the output and errors and returning them in the response.
It's original purpose was to provide an easy and relatively safe way
to deploy a tool hook for Large Language Models to run Python code as
part of their generation process, but it can be used to run any code
given a suitable Docker image in which to run.

## Building

`contained` is built as a single Docker container using the included
Dockerfile. In most cases all you need to do is run:

```shell
docker build --tag contained .
```

If you don't want to build the image yourself, a pre-built image for
`amd64` and `arm64` CPUs can be fetched from Docker Hub using:

```shell
docker pull nickovs/contained
```


## Usage

There are two critical command line (or `docker compose`) options that
are needed in order to run `contained`. The first is obviously to expose
the service port. The second is that since `contained` needs to be able
to start other Docker containers, it also needs access to the docker engine
control socket, typically located at `/var/run/docker.sock` on Unix-like
systems. Thus, you would normally start a stand-alone instance using
something like:

```shell
docker run -d --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock --name contained contained
```

### Configuration

By default `contained` is set up offer service on port 8080. It will run
the provided files using a Python interpreter from a `python:alpine` image.
It creates its own temporary volume for storing the uploaded files
while they are in use. Code will be run as `nobody` with unlimited use of
any available CPU cores for up to 60 seconds.

All of these features can be controlled using the following environment
variables and settings:

* `SERVICE_PORT` may be set to specify a different port to the default 8080
* `DOCKER_IMAGE` may be set to use a different Docker image to the 
default `python:alpine`
* `COMMAND_PREFIX` may be set to change what base command will be 
prepended to the arguments passed by the caller. By default, this will
be `python`.
* `CONTAINED_USER` may be set to either a *numeric* UID or a pair of
*numeric* UID and GID separated by a colon. If this is not set then
both UID and GID default to 65534, the value for `nobody`.
* `CONTAINER_CPU_LIMIT` may be set to a floating point value for the
maximum share of CPU cores that the code can use before being throttled.
A zero value (or the variable not being set) means to explicit limit is
applied.
* `MAX_CONTAINER_RUN_TIME` may be set to an integer number of seconds
to cap the execution time for a container. This represents the elapsed time,
not the CPU time, so code that makes slow calls to the outside world might
need a higher value. The default is 60 seconds.

Additionally, if you prefer to create your own, persistent volume for the
uploads then you can mount this when starting the container; it must be
mounted to the container-side path `/uploads`. Note that currently this
needs to be a volume, not a bind mount, due to the way that the uploads
are re-mounted into sub-containers.

### Request format

Requests are made to the service by posting a JSON object to the `/` path.
The request object contains two keys: 
 * `files`: an array of object that represent the files to be uploaded, each one consisting of
   * `name`: the filename to give to the file
   * `text`: the file's text content
 * `args`. an optional list of command arguments.

If the arguments are missing then the name of the first file in `files` will be used. For example:
```json
{
  "files": [
     {
        "name": "main.py",
        "text": "import math\n\ndef foo(x, y):\n    return math.sin(x) * y\n\nprint(foo(1, 2))\n"
     }
  ],
  "args": [
    "main.py"
  ]
}
```

### Response format

When the container is successfully run the response will be a JSON object
with three keys:
 * `outputs` is a list of output objects that each have three keys:
   * `stream` is either `out` for lines from stdout or `err` for lines from stderr
   * `ts` is the time (in seconds) since the container was started that the output line was captured
   * `text` is the line (or lines) from the stream
 * `exitCode` is the return code from the process that was run in the container
 * `errors` is an optional list of strings of internal error messages

For example, successfully running the request above might yield:

```json
{
  "outputs": [
    {
      "stream": "out",
      "ts": 0.099148375,
      "text": "1.682941969615793\n"
    }
  ],
  "exitCode": 0,
  "errors": null
}
```

## Security considerations

**This tool is potentially dangerous.** 

While the purpose of the tool is to try to provide some sort of sandbox
in which to run untrusted code, care needs to be taken when deploying it.
The `contained` image itself needs to be given access to the Docker engine
control socket, which has many privileges. It relies heavily on the limits
imposed on containers by the Docker runtime for containment of the code
that it runs. Several steps are taken to mitigate the risks:

 * In order the limit the potential for the executed code to 
find ways to break that containment, by default the code is run as the
user `nobody` irrespective of the default for the image. This can be
overridden by setting the `CONTAINED_USER` environment variable.
 * The `contained` image only contains the executable itself rather than
a whole Linux runtime (in Docker terms, it's built from scratch) so that
in the event it has a bug, the scope for exploitation is limited.
 * The remote caller has no control over the configuration of the
sub-container or what volumes get mounted on it.
 * A fresh container, with its own, isolated file space, is created for
each call and destroyed afterward.
 * Container runs are time-limited and may be constrained in the fraction
of CPU capacity they have access to.

Nonetheless, care should be taken when building Docker images for the
runtime to ensure that you do not open up any new avenues by which
untrusted code might escape confinement.

## Building images for the sub-containers

`contained` can run the users' code in any Docker image you care to
provide. The user can upload files that they might need, but these
are generally limited to text files and for the purposes of speed it is
often desirable to anticipate their needs. Thus, while the default image
is `python:alpine`, when running Python code it is usually recommended to
build an image that contains any Python packages that they user might
need.
