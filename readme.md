# Slow JWT blob verification using jose library

Verifying the JWT blob `big.jwt` (800kB) ([source](https://fidoalliance.org/metadata/)) is very slow using the [jose](https://hackage.haskell.org/package/jose) library (~4 minutes)

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

Profiling yields that almost all of allocation happens in https://hackage.haskell.org/package/concise-0.1.0.1/docs/Control-Lens-Cons-Extras.html#v:unfoldr
```
$ cabal run exe:test --enable-profiling -- big.jwt
$ head test.prof
	Wed Sep 15 17:21 2021 Time and Allocation Profiling Report  (Final)

	  test +RTS -p -RTS big.jwt

	total time  =        0.94 secs   (945 ticks @ 1000 us, 1 processor)
	total alloc = 9,308,453,392 bytes  (excludes profiling overheads)

COST CENTRE     MODULE                          SRC                                                  %time %alloc

unfoldr         Control.Lens.Cons.Extras        src/Control/Lens/Cons/Extras.hs:82:1-51               94.8   98.9
```

