# engines lane — Q-068, then Q-058

Owner: Builder / engines. WRITE set: `agent/tools.py`, `agent/upload_tool.py`,
`agent/tests/test_description_gate.py`, `agent/tests/test_truthful_metadata.py`, new tests of my own,
and this file. Everything else is another lane's; patches for files I do not own are recorded here.

Every row below is MEASURED (command + real output) or marked UNVERIFIED. Written as the work
happened, so an entry with no number under it is work in progress, not a silent pass.

## Status

| ticket | state |
|---|---|
| Q-068 canonical coordinate | in progress |
| Q-058 four description defects | not started |

## Run command used for every measurement in this file

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/ -p no:cacheprovider
```

Own throwaway container every time. Nothing is `docker cp`-ed into `apolaki-agent-1`, that container
is never restarted, and `docker compose build` is never run.

## Baseline, before I touched anything

```
$ ... python -m pytest tests/test_truthful_metadata.py tests/test_description_gate.py -p no:cacheprovider -q
......................................................                   [100%]
```

54 passed, 0 failed. Both files are green BEFORE the change, which is what makes the new
Q-068 assertion a real red-to-green rather than a repair of something already broken.

## Q-068 — the same target yields different report evidence depending on the image

### The defect, measured rather than quoted

Both readers were run against the same bytes of the Juice Shop geo-stalking photo
(`/assets/public/images/uploads/magn(et)ificent!-1571814229653.jpg`, HTTP 200, 107952 bytes) inside a
throwaway container off the shipped `apolaki-agent` image, on 2026-08-17:

```
exiftool on PATH: /usr/bin/exiftool

--- exiftool -j -n, the keys `_run_metadata`'s filter keeps ---
'Make' = 'Google'          'Model' = 'Pixel 3 XL'      'Software' = 'paint.net 4.2'
'GPSLatitude'  = 59.4211583333333          <- a float
'GPSLongitude' = 24.8012
'GPSPosition'  = '59.4211583333333 24.8012'
'GPSLatitudeRef' = 'N'  'GPSLongitudeRef' = 'E'  'GPSAltitude' = 71.4  'GPSDOP' = 60.421
'GPSTimeStamp' = '14:12:15'  'GPSDateStamp' = '2019:10:22'  'GPSVersionID' = '2 2 0 0'
'GPSDateTime' = '2019:10:22 14:12:15Z'  'GPSAltitudeRef' = 0
'DeviceModel' = ''  'ProfileCreator' = 'GOOG'

--- native upload_tool.extract_metadata, same bytes ---
'EXIF:Make' = 'Google'     'EXIF:Model' = 'Pixel 3 XL'  'EXIF:Software' = 'paint.net 4.2'
'EXIF:GPSLatitude'  = '59 deg 25\' 16.17" N'   <- a DMS string
'EXIF:GPSLongitude' = '24 deg 48\' 4.32" E'
'EXIF:GPSPosition'  = '59.421158, 24.8012'
'EXIF:GPSDateStamp' = '2019:10:22'
```

So the two readers differ in FOUR ways on the same file, not one:

1. the coordinate spelling — DMS string vs bare float;
2. the pair separator in `GPSPosition` — `", "` vs `" "`;
3. the precision — `59.421158` vs `59.4211583333333`;
4. the key namespace — `EXIF:GPSLatitude` vs `GPSLatitude`.

`_run_metadata` builds its evidence as `"\n".join(f"{k}: {v}")` over that dict, so all four reach a
client-facing finding.

### Scope, stated before the fix so it cannot be quietly widened afterwards

Only (1), (2) and (3) are the defect. (4) is not: exiftool also surfaces `GPSDOP`, `GPSAltitude`,
`GPSTimeStamp`, `GPSVersionID`, `DeviceModel` and `ProfileCreator`, which the native reader genuinely
cannot read. Byte-identical evidence between the two is therefore IMPOSSIBLE and promising it would be
a claim the code cannot keep. The achievable and correct property, and the one under test, is:

> the LOCATION the finding reports is one canonical string, identical whichever reader ran, and no
> reader-specific spelling of that location survives into the evidence.

The key namespace is left alone on purpose: `EXIF:` names the SOURCE the value came from, which is
real information, and flattening it would re-open Q-055's namespacing (XMP and binary EXIF hiding each
other).

### The canonical form

Signed decimal degrees, exactly six decimal places (`%.6f`), hemisphere carried in the sign, latitude
first, `", "` between the pair: `59.421158, 24.801200`.

Chosen because both readers reach it losslessly from the same EXIF rationals, checked by hand:
`59 + 25/60 + 16.17/3600 = 59.42115833...` -> `%.6f` -> `59.421158`, and exiftool's
`59.4211583333333` -> `%.6f` -> `59.421158`. Longitude: `24 + 48/60 + 4.32/3600 = 24.8012` and
exiftool's `24.8012` both -> `24.801200`. Six decimals is ~0.11 m, finer than the source rationals
carry, so the rounding is not throwing away a real distinction.

(sections below are filled in as each step is measured)
