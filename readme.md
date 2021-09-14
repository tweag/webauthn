# Slow JWT blob verification using jose library

Verifying the JWT blob `big.jwt` (800kB) ([source](https://fidoalliance.org/metadata/)) is very slow using the [jose](https://hackage.haskell.org/package/jose) library (~4 minutes), but if profiling is turned on, it becomes very fast (<1 second).

Not as extreme, but the same happens with a smaller `small.jwt` blob (17kB) ([source](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#examples)), which takes


To reproduce slowness:
```
$ cabal run exe:test -- big.jwt +RTS -sstderr
Up to date
Start
Decoded
Finish
 502,762,943,192 bytes allocated in the heap
 116,051,347,208 bytes copied during GC
      39,943,696 bytes maximum residency (47278 sample(s))
       1,234,488 bytes maximum slop
              94 MiB total memory in use (0 MB lost due to fragmentation)

                                     Tot time (elapsed)  Avg pause  Max pause
  Gen  0     350888 colls,     0 par    2.199s   2.274s     0.0000s    0.0005s
  Gen  1     47278 colls,     0 par   136.030s  136.174s     0.0029s    0.0230s

  INIT    time    0.000s  (  0.000s elapsed)
  MUT     time   67.167s  ( 67.106s elapsed)
  GC      time  138.229s  (138.447s elapsed)
  EXIT    time    0.000s  (  0.000s elapsed)
  Total   time  205.396s  (205.554s elapsed)

  %GC     time       0.0%  (0.0% elapsed)

  Alloc rate    7,485,287,376 bytes per MUT second

  Productivity  32.7% of total user, 32.6% of total elapsed
```

Enabling profiling makes it go fast:
```
$ cabal run exe:test --enable-profiling -- big.jwt +RTS -sstderr
Up to date
Start
Decoded
Finish
     897,872,320 bytes allocated in the heap
       3,501,800 bytes copied during GC
       5,484,288 bytes maximum residency (4 sample(s))
       1,230,624 bytes maximum slop
              15 MiB total memory in use (0 MB lost due to fragmentation)

                                     Tot time (elapsed)  Avg pause  Max pause
  Gen  0       853 colls,     0 par    0.004s   0.004s     0.0000s    0.0001s
  Gen  1         4 colls,     0 par    0.001s   0.001s     0.0003s    0.0007s

  INIT    time    0.000s  (  0.000s elapsed)
  MUT     time    0.193s  (  0.192s elapsed)
  GC      time    0.005s  (  0.006s elapsed)
  RP      time    0.000s  (  0.000s elapsed)
  PROF    time    0.000s  (  0.000s elapsed)
  EXIT    time    0.000s  (  0.000s elapsed)
  Total   time    0.198s  (  0.198s elapsed)

  %GC     time       0.0%  (0.0% elapsed)

  Alloc rate    4,660,753,685 bytes per MUT second

  Productivity  97.2% of total user, 97.1% of total elapsed
```

For `small.jwt`, without profiling:
```
$ cabal run exe:test -- small.jwt +RTS -sstderr
Up to date
Reading small.jwt
Verifying..
Finished, wrote output to output.json
     166,469,816 bytes allocated in the heap
       9,911,848 bytes copied during GC
         777,640 bytes maximum residency (72 sample(s))
          38,144 bytes maximum slop
               6 MiB total memory in use (0 MB lost due to fragmentation)

                                     Tot time (elapsed)  Avg pause  Max pause
  Gen  0        86 colls,     0 par    0.002s   0.002s     0.0000s    0.0001s
  Gen  1        72 colls,     0 par    0.013s   0.014s     0.0002s    0.0004s

  INIT    time    0.000s  (  0.000s elapsed)
  MUT     time    0.016s  (  0.016s elapsed)
  GC      time    0.015s  (  0.015s elapsed)
  EXIT    time    0.000s  (  0.000s elapsed)
  Total   time    0.031s  (  0.031s elapsed)

  %GC     time       0.0%  (0.0% elapsed)

  Alloc rate    10,691,652,890 bytes per MUT second

  Productivity  50.5% of total user, 50.3% of total elapsed
```

With profiling:
```
$ cabal run exe:test --enable-profiling -- small.jwt +RTS -sstderr
Up to date
Reading small.jwt
Verifying..
Finished, wrote output to output.json
      20,059,480 bytes allocated in the heap
       1,042,720 bytes copied during GC
         191,704 bytes maximum residency (3 sample(s))
          34,392 bytes maximum slop
               3 MiB total memory in use (0 MB lost due to fragmentation)

                                     Tot time (elapsed)  Avg pause  Max pause
  Gen  0        16 colls,     0 par    0.001s   0.001s     0.0000s    0.0002s
  Gen  1         3 colls,     0 par    0.001s   0.001s     0.0003s    0.0007s

  INIT    time    0.000s  (  0.000s elapsed)
  MUT     time    0.007s  (  0.007s elapsed)
  GC      time    0.001s  (  0.001s elapsed)
  RP      time    0.000s  (  0.000s elapsed)
  PROF    time    0.000s  (  0.000s elapsed)
  EXIT    time    0.000s  (  0.000s elapsed)
  Total   time    0.008s  (  0.008s elapsed)

  %GC     time       0.0%  (0.0% elapsed)

  Alloc rate    2,939,806,703 bytes per MUT second

  Productivity  80.9% of total user, 81.0% of total elapsed
```
