# ldn_mitm

A mitm kip modified from fs_mitm.


ldn_mitm implements LAN connectivity by replacing the system's ldn service.

The original ldn service is only responsible for calling the WiFi service to scan and connect to nearby Switch. ldn_mitm uses the LAN UDP to emulate this scanning process. Therefore ldn_mitm is usually used with [`switch-lan-play`](https://github.com/spacemeowx2/switch-lan-play). A configuration tutorial can be found [here](http://www.lan-play.com/install).

## Features in this fork

This fork adds two things that let you play LDN games with players elsewhere
**without a PC** on your end:

- **On-console broadcast relay** — games send most of their LDN session
  traffic as Wi-Fi broadcasts, which the access point re-floods unreliably and
  slowly (causing lag and, for some titles, dropped sessions). ldn_mitm
  re-sends those broadcasts as reliable per-peer unicast from inside the
  console, removing that lag. This previously required running `switch-lan-play`
  on a PC; now it runs on the console itself.

- **Internet relay (PC-free cross-internet play)** — two consoles on
  **different networks** can play an LDN game together with no PC on either
  end, by relaying both LDN discovery/join *and* the game's session traffic
  through a [`switch-lan-play`](https://github.com/spacemeowx2/switch-lan-play)
  relay server. The console speaks the lan-play protocol directly. You point it
  at a relay server and it behaves like everyone is on the same LAN.

Everything is controlled from the **Tesla overlay** (bundled). None of it
changes normal local LDN unless you turn it on.

## Configuration

Open the Tesla overlay to find these toggles:

| Option | What it does |
| --- | --- |
| **Enabled** | Master switch for ldn_mitm. |
| **Broadcast relay** | On-console broadcast→unicast relay (the lag fix above). Safe to leave on. Saved to `relay.cfg`. |
| **Internet relay** | Turn cross-internet play on/off. Off = normal local LDN. Saved to `relay.cfg`, so it survives reboots. |
| *(server list)* | The relay servers from your config file; select one with **A** (`*` = active). The choice is saved to `relay.cfg`. |
| **Logging** | Write a debug log to `sdmc:/ldn_mitm.log`. |

### Setting up internet play

1. **Get a relay server.** Options:
   - **Self-host the bundled relay** — [`tools/relay_server.py`](tools/relay_server.py),
     a tiny Python 3 script (no dependencies). Run it on a machine both players
     can reach (a low-latency VPS **near both players** gives the best results —
     the relay round-trip is the main source of lag):
     ```bash
     python tools/relay_server.py            # binds UDP 0.0.0.0:11451
     ```
     Forward that UDP port to the machine and give players its public IP/hostname.
   - Self-host the full [`switch-lan-play/server`](https://github.com/spacemeowx2/switch-lan-play), or
   - Use a public [lan-play](https://www.lan-play.com/) server.

2. **List your servers** in `sdmc:/config/ldn_mitm/relay.cfg`, one per line:

   ```
   # <name>  <address[:port]>
   # address may be an IPv4 literal OR a hostname; default port is 11451
   my-vps     203.0.113.10:11451
   public     relay.example.com
   ```

   See [`docs/relay.cfg.example`](docs/relay.cfg.example). Up to 8 servers;
   lines starting with `#` are ignored. Just listing servers does **not** turn
   the relay on.

3. **In the Tesla overlay**, toggle **Internet relay** on and pick a server.
   The toggle is remembered across reboots, and takes effect the next time
   the game opens its host/join menu — no need to restart the game.

4. **Both players** point their consoles at the **same** relay server, then
   host/join the LDN game normally. Keep both consoles on the default DHCP
   network profile (the `10.13.x.x` static profile is only for PC tunneling).

Notes:
- **Set your console's MTU to 1500** (System Settings → Internet → your
  connection → Change Settings → MTU → `1500`). Several games — Street Fighter
  30th Anniversary, Mortal Kombat 11, and other `nn::pia`-based titles —
  require the interface MTU to be 1500, or their session layer silently drops
  all peer traffic (you join, then nothing works). ldn_mitm respects whatever
  MTU your profile has rather than forcing 1500, so you must set it yourself.
  This applies to local play too, not just internet relay.
- A relay server is a shared cloud box, not a per-player PC, so this still
  counts as "no PC on your end".
- Wired Ethernet (USB adapter or dock) on both consoles noticeably reduces
  latency and jitter versus Wi-Fi.

Limitations:
- Internet play is validated for two consoles on different networks. More than
  two, or a mix where some consoles share a LAN and others are remote, is not
  yet tested — it should still connect, but two consoles on the *same* LAN will
  redundantly round-trip their traffic through the relay instead of talking
  directly, which may add jitter. A future update will suppress that.

## Fixes and improvements in this fork

Beyond the two relay features above, this fork fixes a number of games and
hardens the LDN emulation.

### Games

- **Pokémon: Let's Go, Pikachu / Eevee** — link trades and battles now work.
  These use "private" link-code networks, which upstream ldn_mitm never
  implemented; this fork adds them (the session is derived from the link code
  so both consoles agree on it) and fixes a loop where a console kept trying to
  join its own network.
- **Street Fighter 30th Anniversary, Mortal Kombat 11, and other `nn::pia`
  titles** — previously you could "find the room" but the session then died
  ("Connection Failed"). Two causes, both fixed: their session layer needs
  interface MTU 1500 (now respected — set it, see above), and their broadcast
  session traffic was delivered unreliably over Wi-Fi (fixed by the broadcast
  relay).
- **General reliability / lag (e.g. Rayman)** — the on-console broadcast relay
  re-sends games' broadcast session traffic as reliable, ACKed unicast, which
  removes the Wi-Fi lag and the "host goes deaf" failures that broke many
  titles — without needing a PC.

### Stability & correctness

- **Faster scans** — a scan exits as soon as results stop changing instead of
  always blocking a full second, and rebroadcasts to survive UDP packet loss.
- **Failed joins no longer crash games** — a failed join returns the real
  `nn::ldn` error (`2203-0064`) that games expect, instead of a made-up error
  code that made some titles abort.
- **Non-blocking joins with a real timeout** — connecting uses a bounded (5s)
  non-blocking connect and waits for the actual network sync rather than fixed
  sleeps, so a stale or sleeping host can't freeze the game; the join fails
  cleanly with a proper error instead.
- **Self-echo filter** — an access point or relay can echo a console's own
  advertisement back to it; the scan now drops the console's own network so a
  game never tries to join itself (this caused Pokémon LGP's self-connect loop
  and contributed to the Street Fighter failures).
- **Clean teardown** — fixed a poll storm on socket close (the worker spun
  until the game exited), a leaked `nifm` handle that could exhaust sessions
  over rapid retries, and set a proper disconnect reason so games show their
  error UI instead of hanging.
- **Hardening** — `TCP_NODELAY` and a send timeout on the sync socket,
  `SO_REUSEADDR` before bind, `EINTR` resilience in the poll loop, thread-safe
  locking of shared state, and an out-of-bounds fix in the packet compressor.

## Version table

Please try the [GHA nightlies](https://github.com/dogty/ldn_mitm/actions/workflows/nightly.yml) (or the [latest build artifacts](https://github.com/dogty/ldn_mitm/actions/workflows/build.yml)) if you have updated beyond the supported AMS versions.
| ldn_mitm version | Atmosphère version |
| :--------------: | :----------------: |
| [1.25.1](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.25.1)            | [1.11.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.11.1)
| [1.25.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.25.0)            | [1.11.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.11.0)
| [1.24.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.24.0)            | [1.10.2](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.10.2)
| [1.23.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.23.0)            | [1.10.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.10.1)
| [1.20.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.20.0)            | [1.9.3](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.9.3)
| [1.19.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.19.0)            | [1.9.2](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.9.2)
| [1.18.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.18.0)            | [1.9.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.9.1)
| [1.17.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.17.0)            | [1.6.2](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.6.2)
| [1.16.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.16.0)            | [1.5.5](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.5.5)               |
| [1.15.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.15.0)            | [1.5.2](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.5.2)               |
| [1.14.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.14.0)            | [1.4.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.4.0)               |
| [1.13.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.13.0)            | [1.3.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.3.1)               |
| [1.12.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.12.0)            | [1.2.5](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.2.5)               |
| [1.11.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.11.0)            | [1.2.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.2.1)/[1.2.2](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.2.2)               |
| [1.10.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.10.0)            | [1.1.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.1.1)               |
| [1.9.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.9.0)            | [1.0.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.0.0)               |
| [1.8.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.8.0)            | [0.19](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.19.0)/[0.19.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.19.1)               |
| [1.7.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.7.0)            | [0.16.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.16.1)/[0.16.2](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.16.2)/[0.17.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.17.0)/[0.18.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.18.0)/[0.18.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.18.1) |
| [1.6.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.6.0)            | [0.15.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.15.0)/[0.14.4](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.14.4)   |
| [1.5.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.5.0)            | [0.14.0](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.14.0)/[0.14.1](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.14.1)        |
| [1.4.0](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.4.0)            | [0.13](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.13.0)               |
| [1.3.4](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.3.4)            | [0.11](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.11.0)/[0.12](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.12.0)          |
| [1.3.3](https://github.com/spacemeowx2/ldn_mitm/releases/tag/v1.3.3)            | [0.10](https://github.com/Atmosphere-NX/Atmosphere/releases/tag/0.10.0)               |

## Development

Make sure that the submodule is initialized.

```bash
git submodule update --init --recursive
```


### Using Docker

1. Install `Docker` and `docker-compose`.

2. Run `docker-compose up --build`. It runs `make -j8` in the container.


### Using devkitPro

1. Install [`devkitPro`](https://devkitpro.org/wiki/Getting_Started) and install `switch-dev`, `libnx`, `switch-libjpeg-turbo` using `dkp-pacman`.

2. Run `make` command.

Licensing
=====

This software is licensed under the terms of the GPLv2, with exemptions for specific projects noted below.

You can find a copy of the license in the [LICENSE file](LICENSE).

Exemptions:
* The [yuzu Nintendo Switch emulator](https://github.com/yuzu-emu/yuzu) and the [Ryujinx Team and Contributors](https://github.com/orgs/Ryujinx) are exempt from GPLv2 licensing. They are permitted, each at their individual discretion, to instead license any source code authored for the ldn_mitm project as either GPLv2 or later or the [MIT license](https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/licensing_exemptions/MIT_LICENSE). In doing so, they may alter, supplement, or entirely remove the copyright notice for each file they choose to relicense. Neither the ldn_mitm project nor its individual contributors shall assert their moral rights against any of the aforementioned projects.
* [Nintendo](https://github.com/Nintendo) is exempt from GPLv2 licensing and may (at its option) instead license any source code authored for the ldn_mitm project under the Zero-Clause BSD license.

