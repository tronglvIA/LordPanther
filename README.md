# LordPanther -  Process Scanner

---

**This's Cover Project base on https://github.com/Neo23x0/Loki , which was modified and customized. I also want to use this opportunity to express my gratitude and respect to [@Neo23x0](https://github.com/Neo23x0) && [@hasherezade](https://github.com/hasherezade).**

This Cover Project is just only focus on:

```
1. File Name IOC Check on cmd name's process.

2. Yara signature match on process memory.

3. Compares process connection endpoints with CNC IOCs.

4. Process anomaly check.
```

# ## How to

---

## Install

```
$ git clone https://github.com/tronglvIA/LordPanther
$ cd LordPanther
$ $ python -m pip install -r requirements.txt
```

## Run

Open a command line "cmd.exe" as Administrator and run it from there. Remember, the first time run with Internet access to retrieve the signatures.

```
$ python LordPanther.py
```

## Export report to a text file

```
$ python LordPanther.py >> report.txt 2>&1
```

# ## Command Line Options

---

```
usage: LordPanther.py [-h] [--nofilenameioc] [--noyara] [--nothorcnc]
                      [--nothoranomaly] [--nopesieve]

LordPanther - Process Scanner | This's Cover Project base on
https://github.com/Neo23x0/LokiI also want to use this opportunity to express
my gratitude and respect to Neo23x0 && @hasherezade

optional arguments:
  -h, --help       show this help message and exit
  --nofilenameioc  Do not perform IOCs_FileName scans
  --noyara         Do not perform yara process memory scans
  --nothorcnc      Do not perform Command And Control (Process Connection)
                   scans
  --nothoranomaly  Do not perform Thor Process Anomaly scans
  --nopesieve      Do not perform PE-SIEVE scans 
```
