# Mastik Playground

Playground for experiments with Micro-Architectural Attacks using [Mastik](https://github.com/0xADE1A1DE/Mastik) library.

Implementations List:
- Flush+Reload
  - Basic Flush+Reload: [code](FlushReload/BasicFR.c) | [output](FlushReload/BasicFR_output.log)
  - Realistic Flush+Reload on libcrypto.so : [code](FlushReload/RealisticFR.c) | [output](FlushReload/RealisticFR_output.log)
- Prime+Probe
  - Basic Prime+Probe: [code](PrimeProbe/BasicPP_L1.c) | [output](PrimeProbe/BasicPP_L1_output.log)
  - Realistic Prime+Probe w. a Victim thread : [code](PrimeProbe/RealisticPP_L1.c) | [output](PrimeProbe/RealisticPP_L1_output.log) | [plot](PrimeProbe/prime_probe_plot.png) 
