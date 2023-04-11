# Keypair Client Kubernetes Configuration

## Token Generating Script

### Requirements

- Python 3
- Pip3

### Install Dependencies

```
pip3 install -r requirements.txt
```

### Running

Specify the algorithm to use and path to the private key managed by keypair.

```
python3 kube-token.py RS256 /Users/name/mount/mykey
```

## Kubernetes Config File

- Update the template in `kube-config.yaml`.
- Replace `<YOUR_BASE64_ENCODED_CERTIFICATE_AUTHORITY>` with the certificate authority of you keypair agent pod.
- Replace `<KEYPAIR_AGENT_ADDRESS>` with the address of your keypair agent service.
- Repace `path/to/kube-token.py` with the path to the `kube-token.py` script on your local machine.
- Update `<KEY_ALGORITHM>` to the algorithm used by your key.
- Update `path/to/private_key` with the location of the keypair you wish to authenticate with.
