Consider this file as developer's notes, nothing more. It should be removed from the repository at the release stage.

Useful links
------------

- https://github.com/dajohi/dcrdex/blob/3f200df2a2de03501076f8a7351d513ed196887b/dex/networks/zec/tx.go#L61
- https://github.com/guardawallet/lightwalletd/blob/0d3b4ec36faac0bcb4d9dde96ecdd69502f2636e/parser/transaction.go#L187
- https://github.com/dajohi/dcrdex/commit/f6cccaa6a3d29059613ca02f4bbcefa0fb35d7e1
- https://github.com/renproject/mercury/blob/de07b07e33c539d79e356ebe5792036090486dc1/types/btctypes/zec.go#L30
- https://github.com/zcash/zcash/blob/cc815528eda4dd228951bf84bef649f7a9ef0591/src/primitives/transaction.h#L537
- https://github.com/DeckerSU/KomodoOcean/blob/281f59e32f3ce9914cb21746e1a885549aa8d962/src/primitives/transaction.h#L599



System parameters
-----------------

```
/usr/sbin/sysctl net.ipv4.tcp_tw_reuse
/usr/sbin/sysctl net.core.rmem_max
/usr/sbin/sysctl net.core.wmem_max
/usr/sbin/sysctl net.ipv4.tcp_max_syn_backlog
/usr/sbin/sysctl net.core.somaxconn

net.ipv4.tcp_tw_reuse = 2
net.core.rmem_max = 212992
net.core.wmem_max = 212992
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=10000
sudo sysctl -w net.core.somaxconn=10000
```

Train ZSTD
----------

```bash
sudo apt install zstd
# install rosetta-cli
go install github.com/coinbase/rosetta-cli@latest
zstd-train.sh mainnet transaction /data
# or
$(go env GOPATH)/bin/rosetta-cli utils:train-zstd transaction /data/indexer assets/mainnet-transaction.zstd 150000 assets/mainnet-transaction.zstd
```
