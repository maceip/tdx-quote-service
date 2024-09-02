<img src=https://github.com/user-attachments/assets/e3b93253-2079-4344-b272-35e1995f0b1e width="100" height="100">

# qgs & qvl

## build dep

=> ``` fatal error: 'sgx_dcap_ql_wrapper.h' file not found\n")```

get linux-sgx, build sdk & psw, install:
```
sudo dpkg -i libsgx-dcap-quote-verify-dev_1.21.100.3-noble1_amd64.deb
```

## run it from a td then call:
```
curl -X POST -k -H "Content-Type: application/json" -d "ShcEAz3eCNzTelMGIcvUyF9EsBVbU6xw3IVp4sP2Nyv1S3jmZh8bF2XEMzvsd65i" https://localhost:31337/quote
```

