<p align="center">
  <a href="https://www.rosetta-api.org">
    <img width="90%" alt="Rosetta" src="https://github.com/DeckerSU/rosetta-komodo/assets/22120003/7574ebc7-d7f7-4a52-b762-edd5d83ec428">
  </a>
</p>
<h3 align="center">
   Rosetta Komodo
</h3>
<!-- <p align="center">
  <a href="https://travis-ci.com/github/DeckerSU/rosetta-komodo"><img src="https://travis-ci.com/DeckerSU/rosetta-komodo.svg?branch=rosetta-komodo" /></a>
  <a href="https://coveralls.io/github/DeckerSU/rosetta-komodo"><img src="https://coveralls.io/repos/github/DeckerSU/rosetta-komodo/badge.svg" /></a>
  <a href="https://goreportcard.com/report/github.com/DeckerSU/rosetta-komodo"><img src="https://goreportcard.com/badge/github.com/DeckerSU/rosetta-komodo" /></a>
  <a href="https://github.com/DeckerSU/rosetta-komodo/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/DeckerSU/rosetta-komodo.svg" /></a>
</p> -->

## Overview
`rosetta-komodo` provides an implementation of the Rosetta API for the
Komodo network in Golang. If you haven't heard of the Rosetta API, you can find more
information [here](https://rosetta-api.org).

## Usage
As specified in the [Rosetta API Principles](https://www.rosetta-api.org/docs/automated_deployment.html),
all Rosetta implementations must be deployable via Docker and support running via either an
[`online` or `offline` mode](https://www.rosetta-api.org/docs/node_deployment.html#multiple-modes).

**YOU MUST INSTALL DOCKER FOR THE FOLLOWING INSTRUCTIONS TO WORK. YOU CAN DOWNLOAD
DOCKER [HERE](https://www.docker.com/get-started).**

### Install
Running the following commands will create a Docker image called `rosetta-komodo:latest`.

#### From GitHub
To download the pre-built Docker image from the latest release, run:
```text
curl -sSfL https://raw.githubusercontent.com/DeckerSU/rosetta-komodo/rosetta-komodo/install.sh | sh -s
```
_Do not try to install rosetta-komodo using GitHub Packages!_

#### From Source
After cloning this repository, run:
```text
make build-local
```

### Run
Running the following commands will start a Docker container in
[detached mode](https://docs.docker.com/engine/reference/run/#detached--d) with
a data directory at `<working directory>/komodo-data` and the Rosetta API accessible
at port `8080`. Please make sure that `<working directory>/komodo-data` has `nobody:nogroup` ownership.
You can also use a named volume which will be created with the correct ownership using: `-v "komodo-data:/data"`.

#### Mainnet:Online
```text
# create <working directory>/komodo-data with correct ownership
docker run --rm -v "$(pwd)/komodo-data:/data" ubuntu:18.04 bash -c 'chown -R nobody:nogroup /data'
# start rosetta-komodo
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/komodo-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 7771:7771 rosetta-komodo:latest
```
_If you cloned the repository, you can run `make run-mainnet-online`._

#### Adding options to the komodod conf file
The komodod configuration file can be extended by setting the docker command to /app/rosetta-komodo
and using the optional -extend-kmd-conf="" switch. The value of -extend-kmd-conf="" will be
appended to /app/komodo-${NETWORK}.conf, newlines can be set as "\n".
```text
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/komodo-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 7771:7771 rosetta-komodo:latest /app/rosetta-komodo -extend-kmd-conf="reindexfast=1\ndebug=rpc\ndebug=net"
# this command line would append the following to /app/komodo-mainnet.conf
reindexfast=1
debug=rpc
debug=net
```

#### Mainnet:Offline
```text
docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-komodo:latest
```
_If you cloned the repository, you can run `make run-mainnet-offline`._

#### Testnet:Online
```text
# create <working directory>/komodo-data with correct ownership
docker run --rm -v "$(pwd)/komodo-data:/data" ubuntu:18.04 bash -c 'chown -R nobody:nogroup /data'
# start rosetta-komodo
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/komodo-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 19033:19033 rosetta-komodo:latest
```
_If you cloned the repository, you can run `make run-testnet-online`._

#### Testnet:Offline
```text
docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-komodo:latest
```
_If you cloned the repository, you can run `make run-testnet-offline`._


### Network Settings
To increase the load `rosetta-komodo` can handle, it is recommended to tune your OS
settings to allow for more connections. On a linux-based OS, you can run the following
commands ([source](http://www.tweaked.io/guide/kernel)):
```text
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_max_syn_backlog=10000
sysctl -w net.core.somaxconn=10000
sysctl -p (when done)
```
_We have not tested `rosetta-komodo` with `net.ipv4.tcp_tw_recycle` and do not recommend
enabling it._

You should also modify your open file settings to `100000`. This can be done on a linux-based OS
with the command: `ulimit -n 100000`.

### Memory-Mapped Files
`rosetta-komodo` uses [memory-mapped files](https://en.wikipedia.org/wiki/Memory-mapped_file) to
persist data in the `indexer`. As a result, you **must** run `rosetta-komodo` on a 64-bit
architecture (the virtual address space easily exceeds 100s of GBs).

If you receive a kernel OOM, you may need to increase the allocated size of swap space
on your OS. There is a great tutorial for how to do this on Linux [here](https://linuxize.com/post/create-a-linux-swap-file/).

## Architecture
`rosetta-komodo` uses the `syncer`, `storage`, `parser`, and `server` package
from [`rosetta-sdk-go`](https://github.com/coinbase/rosetta-sdk-go) instead
of a new Komodo-specific implementation of packages of similar functionality. Below
you can find a high-level overview of how everything fits together:
```text
                               +------------------------------------------------------------------+
                               |                                                                  |
                               |                 +--------------------------------------+         |
                               |                 |                                      |         |
                               |                 |                 indexer              |         |
                               |                 |                                      |         |
                               |                 | +--------+                           |         |
                               +-------------------+ pruner <----------+                |         |
                               |                 | +--------+          |                |         |
                         +-----v----+            |                     |                |         |
                         |   komodod   |            |              +------+--------+       |         |
                         +-----+----+            |     +--------> block_storage <----+  |         |
                               |                 |     |        +---------------+    |  |         |
                               |                 | +---+----+                        |  |         |
                               +-------------------> syncer |                        |  |         |
                                                 | +---+----+                        |  |         |
                                                 |     |        +--------------+     |  |         |
                                                 |     +--------> coin_storage |     |  |         |
                                                 |              +------^-------+     |  |         |
                                                 |                     |             |  |         |
                                                 +--------------------------------------+         |
                                                                       |             |            |
+-------------------------------------------------------------------------------------------+     |
|                                                                      |             |      |     |
|         +------------------------------------------------------------+             |      |     |
|         |                                                                          |      |     |
|         |                     +---------------------+-----------------------+------+      |     |
|         |                     |                     |                       |             |     |
| +-------+---------+   +-------+---------+   +-------+-------+   +-----------+----------+  |     |
| | account_service |   | network_service |   | block_service |   | construction_service +--------+
| +-----------------+   +-----------------+   +---------------+   +----------------------+  |
|                                                                                           |
|                                         server                                            |
|                                                                                           |
+-------------------------------------------------------------------------------------------+
```

### Optimizations
* Reduce sync time with concurrent block indexing
* Use [Zstandard compression](https://github.com/facebook/zstd) to reduce the size of data stored on disk
without needing to write a manual byte-level encoding

#### Concurrent Block Syncing
To speed up indexing, `rosetta-komodo` uses concurrent block processing
with a "wait free" design (using channels instead of sleeps to signal
which threads are unblocked). This allows `rosetta-komodo` to fetch
multiple inputs from disk while it waits for inputs that appeared
in recently processed blocks to save to disk.
```text
                                                   +----------+
                                                   |   komodod   |
                                                   +-----+----+
                                                         |
                                                         |
          +---------+ fetch block data / unpopulated txs |
          | block 1 <------------------------------------+
          +---------+                                    |
       +-->   tx 1  |                                    |
       |  +---------+                                    |
       |  |   tx 2  |                                    |
       |  +----+----+                                    |
       |       |                                         |
       |       |           +---------+                   |
       |       |           | block 2 <-------------------+
       |       |           +---------+                   |
       |       +----------->   tx 3  +--+                |
       |                   +---------+  |                |
       +------------------->   tx 4  |  |                |
       |                   +---------+  |                |
       |                                |                |
       | retrieve previously synced     |   +---------+  |
       | inputs needed for future       |   | block 3 <--+
       | blocks while waiting for       |   +---------+
       | populated blocks to save to    +--->   tx 5  |
       | disk                               +---------+
       +------------------------------------>   tx 6  |
       |                                    +---------+
       |
       |
+------+--------+
|  coin_storage |
+---------------+
```

## Testing with rosetta-cli
To validate `rosetta-komodo`, [install `rosetta-cli`](https://github.com/coinbase/rosetta-cli#install)
and run one of the following commands:
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/komodo_testnet.json`
* `rosetta-cli check:construction --configuration-file rosetta-cli-conf/komodo_testnet.json`


## Development
* `make deps` to install dependencies
* `make test` to run tests
* `make lint` to lint the source code
* `make salus` to check for security concerns
* `make build-local` to build a Docker image from the local context
* `make coverage-local` to generate a coverage report

## License
This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

© 2020 Coinbase
© 2020   Blockchain Foundation
© 2023 Horizen Foundation
© 2024 DeckerSU