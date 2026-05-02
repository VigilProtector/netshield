# NetShield

NetShield is a network threat and configuration assurance capability within the StratoWard family.
It provides network-level security monitoring, threat detection, and configuration validation.

## Overview

NetShield is part of the VigilProtector StratoWard capability family and focuses on:
- Network threat detection using Suricata as NIDS engine
- Device health monitoring and assurance
- Network configuration validation
- Integration with Picket as plattform-managed Defcon-Sensor-Runtime

## Architecture

NetShield operates as a bounded context within StratoWard and integrates with:
- **Aegis**: For asset identity and metadata
- **PulsePatrol**: For monitoring-nahe Netzsignale
- **SuricataGate**: As cloud-side event router
- **VulnScope**: For network-device vulnerability posture matching

## Getting Started

### Prerequisites

- Go 1.26.0
- Kubernetes cluster with OpenYurt
- Access to VigilProtector platform services

### Installation

```bash
# Clone the repository
git clone git@github.com:vigilprotector/netshield.git
cd netshield

# Build and deploy
make build
make deploy
```

## Configuration

NetShield uses standard VigilProtector configuration patterns. See the [VigilProtector documentation](https://docs.vigilprotector.io) for details.

## Contributing

Please refer to the [VigilProtector contribution guidelines](https://github.com/vigilprotector/vigilprotector/blob/main/CONTRIBUTING.md).

## License

Proprietary - VigilProtector Platform

## Architecture Decision Records

- [ADR-0066](https://docs.vigilprotector.io/adrs/adr-0066): NetShield uses Suricata as NIDS engine

## Related Capabilities

- [StratoWard](https://github.com/vigilprotector/stratoward)
- [VigilNet](https://github.com/vigilprotector/vigilnet)
- [Aegis](https://github.com/vigilprotector/aegis)
- [PulsePatrol](https://github.com/vigilprotector/pulsepatrol)
