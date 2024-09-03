<img src=https://github.com/user-attachments/assets/e3b93253-2079-4344-b272-35e1995f0b1e width="100" height="100">

# tdx quote generation and verification (qgs & qvl)
###### testing only, horrible build deps: (SGXSDX, PSW, DCAP)

## build dep

=> ``` fatal error: 'sgx_dcap_ql_wrapper.h' file not found\n")```

get linux-sgx, build sdk & psw, install:
```
sudo dpkg -i libsgx-dcap-ql-dev_1.21.100.3-noble1_amd64.deb
```

## config

-> tested running in TD with PCCS running on host </br>
-> set your quote collateral network lib to fetch from your PCCS: ```/etc/sgx_default_qcnl.conf```

## generate a quote with 64 bytes of report data:
```
curl --output quote.dat -X POST -H "Content-Type: application/json" -d "ShcEAz3eCNzTelMGIcvUyF9EsBVbU6xw3IVp4sP2Nyv1S3jmZh8bF2XEMzvsd65i"  -k https://localhost:1337/quote
```

## verify a quote:
```
curl --header "Content-Type:application/octet-stream" --data-binary @quote.dat -k https://localhost:1337/verify
```

