    # SigmaOS-vpn-pia

    VPN manager (PIA-style profiles)

    Part of the **SigmaOS** sovereign operating-system ecosystem — a multi-repository
    distribution modelled on Linux Mint and Omarchy Linux. See the parent
    [`SigmaOS`](https://github.com/AaryanSinghChauhan09/SigmaOS) repository for the
    full component index.

    ## Upstream inspirations
    - https://github.com/linuxmint/pia-manager

    ## Design principles applied
    - **Defensive Programming**
- **Fail-Fast**
- **Separation of Concerns**
- **KISS**
- **Deterministic Testing**

    ## Usage
    Verbs: `profiles, connect-plan, status, killswitch-plan`

    ```
    $ sigma-vpn profiles
AU  au.privateinternetaccess.com:1198/udp
$ sigma-vpn connect-plan US-East
remote us-east.privateinternetaccess.com 1198
$ sigma-vpn status status.txt
CONNECTED  in=1048576 out=262144
$ sigma-vpn killswitch-plan on --iface tun0 --vpn-net 10.8.0.0/24
iptables -I OUTPUT -o tun0 -j ACCEPT ...

    ```

    ## Build & test
    ```
    make build
    make test
    ```

    ## Licence
    GNU General Public License v3.0 (FOSS).
