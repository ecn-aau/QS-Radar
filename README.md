# QS-Radar

Scripts to run an experimental Quantum Safe (QS) Radar communication between two endpoints.

## Description

Two scripts, one for each endpoint, run a web application that uses UDP over HTTP to transfer data between each other. Endpoint A is the generator (the Radar), while endpoint B is the receiver (the Command-and-Control center). The applications pull keys using the ETSI014 standard for requesting symmetric cryptographic keys from Quantum Key Distribution (QKD) systems. The applications also use NIST standards for Post-Quantum Cryptography (PQC) for signing encrypted data. The endpoints simulate radar data following the ASTERIX protocol.

A basic data transfer is as follows:
1. Endpoint A simulates a radar track.
2. The app on endpoint A receives the track payload.
3. The app on endpoint A pulls a cryptographic key using ETSI014 and encrypts the payload.
4. The app on endpoint A signs with a PQC standard the encrypted message.
5. The app on endpoint A transmits the signed encrypted message to the app on endpoint B.
6. The app on endpoint B receives the signed encrypted message.
7. The app on endpoint B checks the signature using the public key.
8. The app on endpoint B pulls the same cryptographic key (based on key ID) using ETSI014 and decrypts the payload.
9. The app on endpoint B forwards the radar payload to the radar simulator.
10. Endpoint B shows the radar track.

## Assumptions

The scripts assume the following:
* Key pulling through ETSI014 has to be externally handled.
* The endpoints possess a public-private key pair for signing, with the private key held at endpoint A.

## Requirements

### Hardware

These scripts are run on workstations which are connected to two LANs hosting QKD boxes that constantly generate cryptographic key pairs and support the ETSI014 standard for key pulling. The workstations LANs are bridged to allow for easy communications between the workstations, although other connections through the Internet would suffice (however, the applications are not coded to handle those).

### Software

The scripts use `Python 3.13` in an environment with the following dependencies installed:
```
certifi==2025.1.31
charset-normalizer==3.4.1
idna==3.10
liboqs-python
pycryptodome==3.22.0
requests==2.32.3
urllib3==2.4.0
```

Additionally, `ast-tool-py` is installed and run in parallel to the apps to simulate and showcase the radar tracks.

## Usage

On each endpoint, run `clientA_HTTP` and `clientB_HTTP`, respectively. Moreover, run the following commands in parallel on endpoints A and B, respectively:
```
ast-tool-py --empty-selection --cat 62 1.20 random --sleep 2 | ast-tool-py to-udp --unicast "*" <DESTINATION_IP> <DESTINATION_PORT>
ast-tool-py from-udp --unicast "ch1" <LISTENING_IP> <LISTENING_PORT> | ast-tool-py decode
```

By default, the applications on endpoint A receives the data from the radar simulator at `<DESTINATION_IP>=127.0.0.1` and `<DESTINATION_PORT>=56000`. Meanwhile, the default for the application on endpoint B is `<LISTENING_IP>=127.0.0.1` and `<LISTENING_PORT>=56002`.

## Acknowledgment

Thank you to Martón Reiter for establishing the initial experimental setup during his MSc thesis:
M. Reiter, "Thesis title (placeholder)," *Aalborg University*, Denmark, 2025.
