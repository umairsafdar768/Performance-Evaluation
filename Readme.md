This repository contains the code for measuring various Post Quantum (PQ) and non-PQ key generation, Sign and Verify operation. The algorithms included are vairants of Dilithium, FALCON, SPHINCS+, Kyber, RSA, ECDSA and ECDH.

Segragation between different Signature and Key Exchange PQ and non-PQ algorithms is made in different directories. gcc or any other compiler can be used to compile these C programs. Assuming all required libraries are installed in the standard location, below is an example gcc command to 
```
gcc -o time-keygen-pq time-keygen-pq.c -lcrypto -loqs -lplplot -lm -I/usr/include/plplot -I/usr/include/openssl
```

The plplot library depdendency on an ubuntu could be installed as
```
sudo apt-get install plplot12-driver-cairo plplot-dev plplot11-doc -y
```

Also the [liboqs](https://github.com/open-quantum-safe/liboqs) library should be installed in a default location. Its install instructions can be found on its own repository.