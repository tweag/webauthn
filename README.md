# Reproducing deriving-aeson slowdown with aeson >= 2.0

This assumes Nix is available. Cabal can also be used directly

To measure the time, I recommend `ts` from `moreutils`:
```
nix-shell -p moreutils
```

## Speed with aeson 1.x
```
nix-build -A repro_1 2>&1 | ts -i "%M:%.S"
```

Will print something along the lines of
```
[...]
00:00.000117 Building library for webauthn-0.1.0.0..
00:00.071753 [1 of 1] Compiling Module           ( src/Module.hs, dist/build/Module.o, dist/build/Module.dyn_o )
00:03.185894 running tests
[...]
```

This indicates that the `Compiling Module` step took ~3.19 seconds.

## Speed with aeson 2.x
```
nix-build -A repro_2 2>&1 | ts -i "%M:%.S"
```

Will have a similar output:
```
[...]
00:00.000165 Building library for webauthn-0.1.0.0..
00:00.073955 [1 of 1] Compiling Module           ( src/Module.hs, dist/build/Module.o, dist/build/Module.dyn_o )
00:19.080970 running tests
[...]
```

But here the `Compiling Module` step took ~19.1 seconds!

## Linearity in number of values

The code declares 30 values in an enum to show a clear time difference. The relationship between number of values and the compilation time appears to be linear, both with 1.x and 2.x, but with different constants. Here are the results from a single sample for different numbers of values:

| number of values | time with aeson 1.x | time with aeson 2.x |
| --- | --- | --- |
| 1 | 1.7s | 2.0s |
| 10 | 2.1s | 7.2s |
| 20 | 2.5s | 13.0s |
| 30 | 3.2s | 19.1s |
| 40 | 3.7s | 25.5s |

Taking the measurement for 40 values, each additional value after the first one takes
- (3.7s - 1.7s) / (40 - 1) = 0.05s
- (25.5s - 2.0s) / (40 - 1) = 0.6s

Going by this, the constant factor increased 12-fold!
